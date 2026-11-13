package http3

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/stretchr/testify/require"
)

func TestRetiredEarlyGenerationUnblocksExtendedConnect(t *testing.T) {
	conn, _ := newConnPair(t)
	client := (&Transport{}).NewClientConn(conn)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodConnect, "https://example.com", nil)
	require.NoError(t, err)
	request.Proto = "websocket"
	finished := make(chan error, 1)
	go func() { _, err := client.RoundTrip(request); finished <- err }()
	client.rawConn.retireEarlyData()
	select {
	case err := <-finished:
		require.ErrorIs(t, err, quic.Err0RTTRejected)
		var unopened *errConnUnusable
		require.True(t, errors.As(err, &unopened))
	case <-time.After(time.Second):
		t.Fatal("request kept waiting for retired SETTINGS")
	}
	// Protocol workers finishing late must not close the replacement connection.
	require.NoError(t, client.rawConn.CloseWithError(quic.ApplicationErrorCode(ErrCodeInternalError), "retired worker"))
	require.NoError(t, context.Cause(conn.Context()))
}

func TestEarlyRestartReadyIsOneShot(t *testing.T) {
	conn, _ := newConnPair(t)
	old := (&Transport{}).NewClientConn(conn)
	created := 0
	fresh := &ClientConn{}
	client := newEarlyRestartClient(old, func() *ClientConn { created++; return fresh })
	client.applicationReady() // Normal handshakes must retain their original state.
	require.Zero(t, created)
	client.reject()
	client.applicationReady()
	client.applicationReady()
	require.Equal(t, 1, created)
	active, err := client.active(t.Context())
	require.NoError(t, err)
	require.Same(t, fresh, active)
}
