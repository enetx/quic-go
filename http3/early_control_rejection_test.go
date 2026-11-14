package http3

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/stretchr/testify/require"
)

func TestRejectedEarlyControlGenerationDoesNotCloseQUIC(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	gate, earlySent := make(chan struct{}), make(chan struct{})
	var release, sent sync.Once
	defer release.Do(func() { close(gate) })
	var reject atomic.Bool
	serverTLS := testdata.GetTLSConfig().Clone()
	serverTLS.SetSessionTicketKeys([][32]byte{{1, 2, 3}})
	serverTLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if reject.Load() {
			select {
			case <-gate:
			case <-hello.Context().Done():
				return nil, context.Cause(hello.Context())
			}
		}
		return nil, nil
	}
	serverTLS.UnwrapSession = func(identity []byte, state tls.ConnectionState) (*tls.SessionState, error) {
		session, err := serverTLS.DecryptTicket(identity, state)
		if session != nil && reject.Load() {
			session.EarlyData = false
		}
		return session, err
	}

	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer udp.Close()
	server := &Server{
		TLSConfig:  serverTLS,
		QUICConfig: &quic.Config{Allow0RTT: true},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, "warm")
		}),
	}
	defer server.Close()
	go server.Serve(udp)

	cache := &preconnectSessionCache{
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
		stored:             make(chan struct{}, 4),
	}
	transport := &Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         "localhost",
			RootCAs:            testdata.GetRootCA(),
			ClientSessionCache: cache,
		},
		WireConfig: &WireConfig{FlushEarlySettings: true},
		QUICConfig: &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
			return &settingsWireTrace{onSent: func(packet qlog.PacketSent) {
				if packet.Header.PacketType == qlog.PacketType0RTT {
					for _, frame := range packet.Frames {
						if _, ok := frame.Frame.(*qlog.StreamFrame); ok {
							sent.Do(func() { close(earlySent) })
						}
					}
				}
			}}
		}},
	}
	defer transport.Close()

	request, err := http.NewRequestWithContext(ctx, "GET", "https://"+udp.LocalAddr().String(), nil)
	require.NoError(t, err)
	response, err := transport.RoundTrip(request)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	select {
	case <-cache.stored:
	case <-ctx.Done():
		t.Fatal("missing warm session ticket")
	}
	transport.CloseIdleConnections()
	reject.Store(true)
	conn, err := transport.PreconnectEarly(ctx, udp.LocalAddr().String())
	require.NoError(t, err)
	select {
	case <-earlySent:
	case <-ctx.Done():
		t.Fatal("control stream never used early encryption")
	}

	// Keep the old writer waiting on its stream before TLS retires that stream
	// generation. Rejection is a transport event, not a peer critical-stream reset.
	time.Sleep(10 * time.Millisecond)
	release.Do(func() { close(gate) })
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		t.Fatal("rejected early setup prevented verified TLS readiness")
	}
	require.True(t, conn.ConnectionState().TLS.DidResume)
	require.False(t, conn.ConnectionState().Used0RTT)
	require.NotEmpty(t, conn.ConnectionState().TLS.VerifiedChains)
	transport.mutex.Lock()
	owner := nativeClient(transport.clients[udp.LocalAddr().String()].clientConn)
	transport.mutex.Unlock()
	_, err = owner.RoundTrip(request)
	require.ErrorIs(t, err, quic.Err0RTTRejected)
	select {
	case <-conn.Context().Done():
		t.Fatalf("early worker closed the live QUIC connection: %v", context.Cause(conn.Context()))
	case <-time.After(10 * time.Millisecond):
	}
}
