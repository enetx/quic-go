package http3_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/stretchr/testify/require"
)

type initialSettingsTrace struct {
	sync.Mutex
	first *qlog.PacketSent
}

func (r *initialSettingsTrace) AddProducer() qlogwriter.Recorder { return r }
func (*initialSettingsTrace) Close() error                       { return nil }
func (r *initialSettingsTrace) RecordEvent(event qlogwriter.Event) {
	p, ok := event.(qlog.PacketSent)
	if !ok || p.Header.PacketType != qlog.PacketType1RTT {
		return
	}
	r.Lock()
	defer r.Unlock()
	if r.first == nil {
		p.Frames = append([]qlog.Frame(nil), p.Frames...)
		r.first = &p
	}
}

func TestHTTP3SettingsStagedBeforeHandshakeRelease(t *testing.T) {
	for _, mode := range []string{"default", "custom-early", "custom-full"} {
		t.Run(mode, func(t *testing.T) { testHTTP3SettingsStagedBeforeHandshakeRelease(t, mode) })
	}
}

func testHTTP3SettingsStagedBeforeHandshakeRelease(t *testing.T, mode string) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tlsConfig := testdata.GetTLSConfig()
	listener, err := quic.ListenAddr("127.0.0.1:0", http3.ConfigureTLSConfig(tlsConfig), nil)
	require.NoError(t, err)
	defer listener.Close()
	server := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })}
	defer server.Close()
	go server.ServeListener(listener)
	var ready atomic.Int32
	var released atomic.Bool
	trace := new(initialSettingsTrace)
	config := &quic.Config{ClientHandshake: &quic.ClientHandshake{
		DisableConnectionIDRotation: true, OmitInitialAckOnHandshake: true,
		OnApplicationReady: func(c *quic.Conn) {
			ready.Add(1)
			select {
			case <-c.HandshakeComplete():
				released.Store(true)
			default:
			}
		},
	}, Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }}
	transport := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, QUICConfig: config, WireConfig: &http3.WireConfig{CoalesceInitialSettings: true, ControlGreaseFrames: func() ([]http3.GreaseFrame, error) {
		return []http3.GreaseFrame{{Type: 33, Payload: []byte("abc")}}, nil
	}}}
	defer transport.Close()
	if mode != "default" {
		transport.Dial = func(ctx context.Context, addr string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
			if mode == "custom-early" {
				return quic.DialAddrEarly(ctx, addr, tlsConfig, config)
			}
			return quic.DialAddr(ctx, addr, tlsConfig, config)
		}
	}
	request, err := http.NewRequestWithContext(ctx, "GET", "https://"+listener.Addr().String(), nil)
	require.NoError(t, err)
	response, err := transport.RoundTrip(request)
	require.NoError(t, err)
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, "ok", string(data))
	require.EqualValues(t, 1, ready.Load())
	require.False(t, released.Load(), "application callback ran after handshake channel release")
	trace.Lock()
	defer trace.Unlock()
	require.NotNil(t, trace.first)
	var control bool
	for _, frame := range trace.first.Frames {
		if stream, ok := frame.Frame.(*qlog.StreamFrame); ok && stream.StreamID == 2 {
			control = true
		}
		require.IsNotType(t, &qlog.RetireConnectionIDFrame{}, frame.Frame)
	}
	require.True(t, control, "first 1-RTT packet did not carry SETTINGS")
	require.NotNil(t, config.ClientHandshake.OnApplicationReady, "caller config was mutated")
}

func TestHTTP3CoalescedSettingsBackpressure(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(map[bool]string{false: "drain", true: "cancel"}[cancel], func(t *testing.T) {
			payload := bytes.Repeat([]byte{42}, 4096)
			p := newQPACKStartupPair(t, &http3.QPACKConfig{StreamOrder: []http3.QPACKStreamType{http3.QPACKDecoderStream, http3.QPACKEncoderStream}}, &quic.Config{InitialStreamReceiveWindow: 1024, MaxStreamReceiveWindow: 1024, MaxIncomingUniStreams: 3}, &http3.WireConfig{CoalesceInitialSettings: true, ControlGreaseFrames: func() ([]http3.GreaseFrame, error) { return []http3.GreaseFrame{{Type: 33, Payload: payload}}, nil }})
			if cancel {
				require.NoError(t, p.client.CloseWithError(0, "cancel blocked SETTINGS"))
				_, err := p.h3.OpenRequestStream(p.ctx)
				require.Error(t, err)
				return
			}
			control := wireControl(t, p)
			require.EqualValues(t, 2, control.StreamID())
			kind, data := readWireFrame(t, control)
			require.EqualValues(t, 33, kind)
			require.Equal(t, payload, data)
			p.sendHeaders(t)
			// Exactly one control stream plus the two reserved QPACK streams.
			_, err := p.client.OpenUniStream()
			var limit *quic.StreamLimitReachedError
			require.ErrorAs(t, err, &limit)
		})
	}
}

func TestHTTP3CoalescedSettingsFactoryError(t *testing.T) {
	failure := errors.New("initial control factory failed")
	p := newQPACKStartupPair(t, nil, nil, &http3.WireConfig{CoalesceInitialSettings: true, ControlGreaseFrames: func() ([]http3.GreaseFrame, error) { return nil, failure }})
	_, err := p.h3.OpenRequestStream(p.ctx)
	require.ErrorIs(t, err, failure)
}
