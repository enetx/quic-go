package http3

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/stretchr/testify/require"
)

func TestConnectionStartReachesSharedAndLatePreparationWaiters(t *testing.T) {
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer udp.Close()
	server := &Server{TLSConfig: testdata.GetTLSConfig()}
	defer server.Close()
	go server.Serve(udp)
	resolving, resolved, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var dials atomic.Int32
	transport := &Transport{
		TLSClientConfig: &tls.Config{ServerName: "localhost", RootCAs: testdata.GetRootCA()},
		Dial: func(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
			dials.Add(1)
			close(resolving)
			select {
			case <-resolved:
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			}
			NotifyConnectionStarted(ctx)
			NotifyConnectionStarted(ctx)
			select {
			case <-finish:
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			}
			return quic.DialAddr(ctx, address, tlsConfig, config)
		},
	}
	defer transport.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	address := udp.LocalAddr().String()
	begin := func(ctx context.Context) (<-chan struct{}, <-chan error) {
		started, result := make(chan struct{}, 2), make(chan error, 1)
		go func() {
			_, err := transport.PreconnectWithOptions(ctx, address, PreconnectOptions{
				OnConnectionStarted: func() { started <- struct{}{} },
			})
			result <- err
		}()
		return started, result
	}
	firstStarted, first := begin(ctx)
	<-resolving
	secondContext, cancelSecond := context.WithCancel(ctx)
	defer cancelSecond()
	secondStarted, second := begin(secondContext)
	require.Eventually(t, func() bool {
		transport.mutex.Lock()
		defer transport.mutex.Unlock()
		return transport.clients[address].useCount.Load() == 2
	}, time.Second, time.Millisecond)
	select {
	case <-firstStarted:
		t.Fatal("start notification preceded resolution")
	default:
	}
	close(resolved)
	select {
	case <-firstStarted:
	case <-ctx.Done():
		t.Fatal("first waiter missed connection start")
	}
	select {
	case <-secondStarted:
	case <-ctx.Done():
		t.Fatal("shared waiter missed connection start")
	}
	lateStarted, late := begin(ctx)
	select {
	case <-lateStarted:
	case <-ctx.Done():
		t.Fatal("late waiter waited for the handshake instead of observing start")
	}
	cancelSecond()
	require.ErrorIs(t, <-second, context.Canceled)
	close(finish)
	require.NoError(t, <-first)
	require.NoError(t, <-late)
	require.Empty(t, firstStarted, "repeated provider notifications must not duplicate observer calls")
	require.Empty(t, secondStarted)
	require.Empty(t, lateStarted)
	require.EqualValues(t, 1, dials.Load())
}
