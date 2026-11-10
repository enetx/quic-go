package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/stretchr/testify/require"
)

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
