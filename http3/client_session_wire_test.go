package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	dynamic "github.com/enetx/quic-go/internal/qpack"
	transportlog "github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/quic-go/quicvarint"
	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

type settingsWireTrace struct {
	onSent func(transportlog.PacketSent)
}

func (r *settingsWireTrace) AddProducer() qlogwriter.Recorder { return r }
func (r *settingsWireTrace) Close() error                     { return nil }
func (r *settingsWireTrace) RecordEvent(event qlogwriter.Event) {
	if packet, ok := event.(transportlog.PacketSent); ok {
		r.onSent(packet)
	}
}

// This independent raw peer decodes the received field section with a new QPACK
// table for each connection. Its second handshake cannot finish until an actual
// 0-RTT request packet is sent. A nonzero Required Insert Count then proves that
// the client used remembered SETTINGS before receiving this connection's frame.
func TestClientTicketSettingsEnableDynamicQPACKOnWire(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	earlySent := make(chan struct{})
	var once sync.Once
	var handshakes atomic.Int32
	serverTLS := getTLSConfig()
	serverTLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		if handshakes.Add(1) > 1 {
			select {
			case <-earlySent:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return nil, nil
	}
	packet := newUDPConnLocalhost(t)
	listener, err := quic.ListenEarly(packet, serverTLS, &quic.Config{Allow0RTT: true})
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close(); packet.Close() })
	type observation struct {
		required       byte
		fields         []base.HeaderField
		resumed, early bool
	}
	observed, failures := make(chan observation, 4), make(chan error, 8)
	go func() {
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			go func() {
				defer conn.CloseWithError(0, "")
				decoder := dynamic.NewDecoder(4096, 16, nil)
				defer decoder.Close(context.Canceled)
				go func() {
					for {
						stream, err := conn.AcceptUniStream(ctx)
						if err != nil {
							return
						}
						go func() {
							r := quicvarint.NewReader(stream)
							typ, err := quicvarint.Read(r)
							if err != nil {
								return
							}
							if typ == 2 {
								decoder.ReadEncoder(stream)
							} else {
								io.Copy(io.Discard, stream)
							}
						}()
					}
				}()
				select {
				case <-conn.HandshakeComplete():
				case <-ctx.Done():
					return
				}
				control, err := conn.OpenUniStreamSync(ctx)
				if err != nil {
					failures <- err
					return
				}
				_, err = control.Write((&settingsFrame{MaxFieldSectionSize: 65536, Other: orderedTestSettings(map[uint64]uint64{1: 4096, 7: 16})}).Append([]byte{0}))
				if err != nil {
					failures <- err
					return
				}
				for {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					frame, err := (&frameParser{r: stream}).ParseNext(nil)
					if err != nil {
						failures <- err
						return
					}
					header, ok := frame.(*headersFrame)
					if !ok {
						failures <- fmt.Errorf("expected HEADERS, got %T", frame)
						return
					}
					block := make([]byte, header.Length)
					if _, err := io.ReadFull(stream, block); err != nil {
						failures <- err
						return
					}
					fields, err := decoder.Decode(ctx, uint64(stream.StreamID()), block, 65536, nil)
					if err != nil {
						failures <- err
						return
					}
					observed <- observation{block[0], fields, conn.ConnectionState().TLS.DidResume, conn.ConnectionState().Used0RTT}
					response := (&headersFrame{Length: 3}).Append(nil)
					response = append(response, 0, 0, 0xd9) // static :status = 200
					response = (&dataFrame{Length: 2}).Append(response)
					if _, err := stream.Write(append(response, 'o', 'k')); err != nil {
						failures <- err
						return
					}
					stream.Close()
				}
			}()
		}
	}()
	cache := &settingsRecordingCache{}
	clientTLS := getTLSClientConfig()
	clientTLS.ClientSessionCache = cache
	transport := &Transport{TLSClientConfig: clientTLS,
		QPACKConfig: &QPACKConfig{DynamicTable: true, EncoderTableCapacity: 4096, StreamOrder: []QPACKStreamType{QPACKEncoderStream}},
		QUICConfig: &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
			return &settingsWireTrace{onSent: func(packet transportlog.PacketSent) {
				if packet.Header.PacketType != transportlog.PacketType0RTT {
					return
				}
				for _, frame := range packet.Frames {
					if stream, ok := frame.Frame.(*transportlog.StreamFrame); ok && stream.StreamID == 0 {
						once.Do(func() { close(earlySent) })
					}
				}
			}}
		}},
	}
	t.Cleanup(func() { transport.Close() })
	for attempt := range 3 {
		req, err := http.NewRequestWithContext(ctx, MethodGet0RTT, "https://"+listener.Addr().String(), nil)
		require.NoError(t, err)
		req.Header.Set("X-Ticket-Probe", "fresh-dynamic-entry")
		response, err := transport.RoundTrip(req)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.True(t, bytes.Equal(body, []byte("ok")))
		select {
		case got := <-observed:
			t.Logf("connection %d: resumed=%t early=%t required-insert-count-byte=%d", attempt+1, got.resumed, got.early, got.required)
			require.Contains(t, got.fields, base.HeaderField{Name: "x-ticket-probe", Value: "fresh-dynamic-entry"})
			require.Equal(t, attempt > 0, got.resumed)
			require.Equal(t, attempt > 0, got.early)
			if attempt > 0 {
				require.NotZero(t, got.required, "restored SETTINGS must enable early dynamic references")
			}
		case err := <-failures:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		require.Eventually(t, func() bool {
			state, ok := cache.Get("")
			if !ok {
				return false
			}
			_, ok = ClientSessionSettings(state)
			return ok
		}, time.Second, time.Millisecond)
		transport.CloseIdleConnections()
	}
}
