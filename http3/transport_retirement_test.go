package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/stretchr/testify/require"
)

func TestRetireConnectionsPreservesBodiesAndRejectsReuse(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(map[bool]string{false: "native", true: "restart"}[restart], func(t *testing.T) {
			transport, port, dials := reuseTestTransport(t)
			transport.EarlyDataRestart = restart
			transport.ConnectionReusePolicy = func(context.Context, ConnectionReuseInfo) bool { return true }
			address := "localhost:" + port
			response := reuseRequest(t, transport, address, false)
			defer response.Body.Close()
			old := transport.clients[address]
			require.NotEmpty(t, old.conn.ConnectionState().TLS.VerifiedChains)

			transport.RetireConnections()
			transport.RetireConnections()
			require.False(t, transport.HasCachedConnection(t.Context(), address))
			require.Contains(t, transport.retired, old)
			require.NoError(t, old.conn.Context().Err(), "active body must survive")

			// Coalescing must not bring a retired owner back into the pool.
			reuseRequest(t, transport, "127.0.0.1:"+port, true)
			require.EqualValues(t, 2, dials.Load())
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			require.Equal(t, address, string(body))
			require.NoError(t, response.Body.Close())
			require.Eventually(t, func() bool { return old.conn.Context().Err() != nil }, time.Second, time.Millisecond)
			require.Eventually(t, func() bool {
				transport.mutex.Lock()
				defer transport.mutex.Unlock()
				_, retained := transport.retired[old]
				return !retained
			}, time.Second, time.Millisecond)
		})
	}
}

func TestRetireConnectionsClosesIdleAndPendingButTransportRemainsUsable(t *testing.T) {
	transport, port, _ := reuseTestTransport(t)
	address := "localhost:" + port
	reuseRequest(t, transport, address, true)
	old := transport.clients[address]
	transport.RetireConnections()
	require.Eventually(t, func() bool { return old.conn.Context().Err() != nil }, time.Second, time.Millisecond)
	reuseRequest(t, transport, address, true)
	require.NotSame(t, old, transport.clients[address])

	started := make(chan struct{})
	blocked := &Transport{Dial: func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, context.Cause(ctx)
	}}
	defer blocked.Close()
	result := make(chan error, 1)
	go func() { result <- blocked.Preconnect(t.Context(), "localhost:443") }()
	<-started
	blocked.RetireConnections()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("retirement did not cancel pending dial")
	}
	require.NoError(t, blocked.Close())
	blocked.RetireConnections()
	require.Empty(t, blocked.clients)
	require.Empty(t, blocked.retired)
}

func TestRetirementDoesNotReplaceARealCriticalStreamFailure(t *testing.T) {
	transport, port, _ := reuseTestTransport(t)
	address := "localhost:" + port
	response := reuseRequest(t, transport, address, false)
	defer response.Body.Close()
	old := transport.clients[address]
	transport.RetireConnections()
	require.NoError(t, old.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), "test"))
	_, err := io.ReadAll(response.Body)
	// Data already buffered may still be read; the connection's actual cause
	// must remain the critical-stream error instead of retirement cancellation.
	if err != nil {
		require.NotErrorIs(t, err, context.Canceled)
	}
	var app *quic.ApplicationError
	require.True(t, errors.As(context.Cause(old.conn.Context()), &app))
	require.Equal(t, quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), app.ErrorCode)
}

func TestRetirementSurvivesRejectedGenerationReplacement(t *testing.T) {
	for _, retireFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "replacement-first", true: "retirement-first"}[retireFirst], func(t *testing.T) {
			conn, _ := newConnPair(t)
			transport := &Transport{}
			old := transport.NewClientConn(conn)
			client := newEarlyRestartClient(old, func() *ClientConn { return transport.NewClientConn(conn) })
			client.reject()
			if retireFirst {
				client.retire()
				client.applicationReady()
			} else {
				client.applicationReady()
				client.retire()
			}
			require.True(t, client.current.Load().rawConn.retiring.Load())
			require.Error(t, client.current.Load().goAwayCtx.Err())
			select {
			case <-conn.Context().Done():
			case <-time.After(time.Second):
				t.Fatal("replacement resurrected a retired idle connection")
			}
		})
	}
}
