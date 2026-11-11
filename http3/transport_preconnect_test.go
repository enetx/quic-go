package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/stretchr/testify/require"
)

type preconnectSessionCache struct {
	tls.ClientSessionCache
	stored chan struct{}
}

func (c *preconnectSessionCache) Put(key string, state *tls.ClientSessionState) {
	c.ClientSessionCache.Put(key, state)
	if state != nil {
		select {
		case c.stored <- struct{}{}:
		default:
		}
	}
}

func TestPreconnectEarlyKeepsPooledConnectionBeforeHandshake(t *testing.T) {
	gate := make(chan struct{})
	var release sync.Once
	tlsConfig := testdata.GetTLSConfig().Clone()
	var handshakes, calls atomic.Int32
	tlsConfig.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		if handshakes.Add(1) == 1 {
			return nil, nil
		}
		select {
		case <-gate:
			return nil, nil
		case <-info.Context().Done():
			return nil, info.Context().Err()
		}
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer udp.Close()
	server := &Server{TLSConfig: tlsConfig, QUICConfig: &quic.Config{Allow0RTT: true}, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.Write([]byte("ok")) })}
	defer server.Close()
	go server.Serve(udp)
	cache := &preconnectSessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(4), stored: make(chan struct{}, 4)}
	tr := &Transport{TLSClientConfig: &tls.Config{ServerName: "localhost", RootCAs: testdata.GetRootCA(), ClientSessionCache: cache}}
	defer tr.Close()
	defer release.Do(func() { close(gate) })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+udp.LocalAddr().String(), nil)
	require.NoError(t, err)
	response, err := tr.RoundTrip(req)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	response.Body.Close()
	select {
	case <-cache.stored:
	case <-ctx.Done():
		t.Fatal("no session ticket")
	}
	tr.CloseIdleConnections()
	conn, err := tr.PreconnectEarly(ctx, udp.LocalAddr().String())
	require.NoError(t, err)
	select {
	case <-conn.HandshakeComplete():
		t.Fatal("early preparation waited for the gated handshake")
	default:
	}
	require.EqualValues(t, 1, calls.Load(), "preparation must not send a request")
	confirmed := make(chan error, 1)
	go func() { confirmed <- tr.Preconnect(ctx, udp.LocalAddr().String()) }()
	release.Do(func() { close(gate) })
	require.NoError(t, <-confirmed)
	require.EqualValues(t, 2, handshakes.Load(), "both preparations must share the same pooled connection")
	response, err = tr.RoundTrip(req)
	require.NoError(t, err)
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	require.EqualValues(t, 2, calls.Load())
}

func TestCoalescedPreparationUsesSelectedAddressConnection(t *testing.T) {
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer udp.Close()
	var requests atomic.Int32
	server := &Server{TLSConfig: testdata.GetTLSConfig(), Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); io.WriteString(w, "selected") })}
	defer server.Close()
	go server.Serve(udp)
	tr := &Transport{TLSClientConfig: &tls.Config{ServerName: "localhost", RootCAs: testdata.GetRootCA()}, WireConfig: &WireConfig{CoalesceInitialSettings: true}, Dial: func(ctx context.Context, _ string, config *tls.Config, q *quic.Config) (*quic.Conn, error) {
		// Both candidates invoke the application-ready hook. Returning the
		// second simulates an address race whose first ready candidate loses.
		first, err := quic.DialAddr(ctx, udp.LocalAddr().String(), config, q)
		if err != nil {
			return nil, err
		}
		defer first.CloseWithError(0, "unselected address")
		return quic.DialAddr(ctx, udp.LocalAddr().String(), config, q)
	}}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+udp.LocalAddr().String(), nil)
	require.NoError(t, err)
	response, err := tr.RoundTrip(req)
	require.NoError(t, err)
	data, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, "selected", string(data))
	require.EqualValues(t, 1, requests.Load())
}

func TestPreconnectHTTP3PoolWithoutRequest(t *testing.T) {
	var calls, dials atomic.Int32
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer udp.Close()
	s := &Server{TLSConfig: testdata.GetTLSConfig(), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte("ok")) })}
	defer s.Close()
	go s.Serve(udp)
	tr := &Transport{TLSClientConfig: &tls.Config{ServerName: "localhost", RootCAs: testdata.GetRootCA()}, Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
		dials.Add(1)
		return quic.DialAddr(ctx, addr, tlsConf, conf)
	}}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, tr.Preconnect(ctx, udp.LocalAddr().String()))
	require.Zero(t, calls.Load())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+udp.LocalAddr().String(), nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	_, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	require.EqualValues(t, 1, calls.Load())
	require.EqualValues(t, 1, dials.Load())
	require.NoError(t, tr.Preconnect(ctx, udp.LocalAddr().String()))
	require.EqualValues(t, 1, dials.Load())
}

func TestPreconnectHTTP3SharedDialCancellation(t *testing.T) {
	started, stop := make(chan struct{}), make(chan struct{})
	tr := &Transport{Dial: func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
		close(started)
		<-ctx.Done()
		close(stop)
		return nil, context.Cause(ctx)
	}}
	defer tr.Close()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- tr.Preconnect(ctx, "localhost:443") }()
	<-started
	// A second waiting caller shares the same native pool entry.
	tr.mutex.Lock()
	shared := tr.clients["localhost:443"]
	tr.mutex.Unlock()
	ctx2, cancel2 := context.WithCancel(t.Context())
	done2 := make(chan error, 1)
	go func() { done2 <- tr.Preconnect(ctx2, "localhost:443") }()
	require.Eventually(t, func() bool { return shared.useCount.Load() == 2 }, time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	select {
	case <-stop:
		t.Fatal("one canceled caller killed a shared dial")
	default:
	}
	cancel2()
	require.ErrorIs(t, <-done2, context.Canceled)
	select {
	case <-stop:
	case <-time.After(time.Second):
		t.Fatal("abandoned dial not canceled")
	}
	require.Empty(t, tr.clients)
	require.Error(t, tr.Preconnect(t.Context(), "bad address"))
	ctx3, cancel3 := context.WithCancel(t.Context())
	cancel3()
	require.True(t, errors.Is(tr.Preconnect(ctx3, "localhost:443"), context.Canceled))
}
