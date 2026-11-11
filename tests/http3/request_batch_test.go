package http3_test

import (
	"context"
	"crypto/tls"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

type requestBatchTrace struct {
	sync.Mutex
	packets []qlog.PacketSent
}

func (r *requestBatchTrace) AddProducer() qlogwriter.Recorder { return r }
func (*requestBatchTrace) Close() error                       { return nil }
func (r *requestBatchTrace) RecordEvent(e qlogwriter.Event) {
	if p, ok := e.(qlog.PacketSent); ok && p.Header.PacketType == qlog.PacketType1RTT {
		p.Frames = append([]qlog.Frame(nil), p.Frames...)
		r.Lock()
		r.packets = append(r.packets, p)
		r.Unlock()
	}
}

func TestHTTP3CoalescesInitialPriorityHeadersAndFIN(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	listener, err := quic.ListenAddr("127.0.0.1:0", http3.ConfigureTLSConfig(testdata.GetTLSConfig()), nil)
	require.NoError(t, err)
	defer listener.Close()
	server := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		io.WriteString(w, "ok"+string(body))
	})}
	defer server.Close()
	go server.ServeListener(listener)
	trace := new(requestBatchTrace)
	tr := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: testdata.GetRootCA(), ServerName: "localhost"}, QUICConfig: &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }}, WireConfig: &http3.WireConfig{CoalesceInitialSettings: true, CoalesceRequestHeaders: true, SendPriorityUpdates: true}}
	defer tr.Close()
	for i := 0; i < 30; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+listener.Addr().String(), nil)
		req.Header.Set("Priority", "u=0, i")
		rsp, err := tr.RoundTrip(req)
		require.NoError(t, err)
		body, err := io.ReadAll(rsp.Body)
		rsp.Body.Close()
		require.NoError(t, err)
		require.Equal(t, "ok", string(body))
	}
	trace.Lock()
	defer trace.Unlock()
	for i := 0; i < 30; i++ {
		id := quic.StreamID(4 * i)
		found := false
		for _, p := range trace.packets {
			controlAt, requestAt := -1, -1
			for j, f := range p.Frames {
				if sf, ok := f.Frame.(*qlog.StreamFrame); ok {
					if sf.StreamID == 2 {
						controlAt = j
					}
					if sf.StreamID == id && sf.Length > 0 {
						requestAt = j
						require.True(t, sf.Fin, "request %d has a separate FIN", i)
					}
				}
			}
			if requestAt >= 0 {
				require.GreaterOrEqual(t, controlAt, 0, "request %d has a separate priority update", i)
				require.Less(t, controlAt, requestAt)
				found = true
				break
			}
		}
		require.True(t, found, "no packet for request %d", i)
	}
}

func TestHTTP3CoalescingKeepsManualStreamOpen(t *testing.T) {
	p := newQPACKStartupPair(t, nil, nil, &http3.WireConfig{CoalesceRequestHeaders: true, SendPriorityUpdates: true})
	control := wireControl(t, p)
	stream, err := p.h3.OpenRequestStream(p.ctx)
	require.NoError(t, err)
	req, _ := http.NewRequestWithContext(p.ctx, "GET", "https://localhost/", nil)
	req.Header.Set("Priority", "u=1")
	require.NoError(t, stream.SendRequestHeader(req))
	_, err = stream.Write([]byte("manual body"))
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	remote, err := p.server.AcceptStream(p.ctx)
	require.NoError(t, err)
	r := quicvarint.NewReader(remote)
	kind, err := quicvarint.Read(r)
	require.NoError(t, err)
	require.EqualValues(t, 1, kind)
	n, err := quicvarint.Read(r)
	require.NoError(t, err)
	_, err = io.CopyN(io.Discard, remote, int64(n))
	require.NoError(t, err)
	kind, err = quicvarint.Read(r)
	require.NoError(t, err)
	require.Zero(t, kind)
	n, err = quicvarint.Read(r)
	require.NoError(t, err)
	body, err := io.ReadAll(remote)
	require.NoError(t, err)
	require.EqualValues(t, len("manual body"), n)
	require.Equal(t, "manual body", string(body))
	kind2, _ := readWireFrame(t, control)
	require.EqualValues(t, 0xf0700, kind2)
}

func TestHTTP3CoalescedRequestSurvivesControlBackpressure(t *testing.T) {
	p := newQPACKStartupPair(t, nil, &quic.Config{InitialStreamReceiveWindow: 1024, MaxStreamReceiveWindow: 1024}, &http3.WireConfig{CoalesceRequestHeaders: true, SendPriorityUpdates: true, ControlGreaseFrames: func() ([]http3.GreaseFrame, error) {
		return []http3.GreaseFrame{{Type: 33, Payload: make([]byte, 4096)}}, nil
	}})
	control := wireControl(t, p)
	stream, err := p.h3.OpenRequestStream(p.ctx)
	require.NoError(t, err)
	req, _ := http.NewRequestWithContext(p.ctx, "GET", "https://localhost/", nil)
	req.Header.Set("Priority", "u=0, i")
	require.NoError(t, stream.SendRequestHeader(req))
	require.NoError(t, stream.Close())
	remote, err := p.server.AcceptStream(p.ctx)
	require.NoError(t, err)
	deadline, _ := p.ctx.Deadline()
	remote.SetReadDeadline(deadline)
	data, err := io.ReadAll(remote)
	require.NoError(t, err)
	require.NotEmpty(t, data, "HEADERS waited for the blocked control stream")
	kind, payload := readWireFrame(t, control)
	require.EqualValues(t, 33, kind)
	require.Len(t, payload, 4096)
	kind, payload = readWireFrame(t, control)
	require.EqualValues(t, 0xf0700, kind)
	id, n, err := quicvarint.Parse(payload)
	require.NoError(t, err)
	require.EqualValues(t, stream.StreamID(), id)
	require.Equal(t, "u=0, i", string(payload[n:]))
}
