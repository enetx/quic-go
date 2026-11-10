package http3

import (
	"context"
	"testing"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

// Private queue access makes backpressure deterministic, without socket timing.
func TestPriorityUpdaterBackpressure(t *testing.T) {
	conn, _ := newConnPair(t)
	c := &ClientConn{rawConn: &rawConn{conn: conn}, wireConfig: &WireConfig{}}
	c.controlWriter = &clientControlWriter{owner: c.rawConn, queue: make(chan []byte, 1)}
	c.controlWriter.queue <- []byte("occupied")
	done := make(chan struct{})
	p := &PriorityUpdater{request: context.Background(), connection: conn.Context(), done: done, ready: true, urgency: 3,
		send: func(u int8, i bool) error { return c.enqueuePriorityUpdate(4, u, i) }}
	require.ErrorContains(t, p.Update(2, true), "queue is full")
	<-c.controlWriter.queue
	require.NoError(t, p.Update(2, true))
	data := <-c.controlWriter.queue
	kind, n, err := quicvarint.Parse(data)
	require.NoError(t, err)
	require.EqualValues(t, 0xf0700, kind)
	_, m, err := quicvarint.Parse(data[n:])
	require.NoError(t, err)
	id, k, err := quicvarint.Parse(data[n+m:])
	require.NoError(t, err)
	require.EqualValues(t, 4, id)
	require.Equal(t, "u=2, i", string(data[n+m+k:]))
	require.NoError(t, p.Update(2, true))
	require.Empty(t, c.controlWriter.queue)
	close(done)
	require.ErrorIs(t, p.Update(2, true), ErrRequestCompleted)
}

func TestPriorityUpdaterUnreadyAndClosedConnection(t *testing.T) {
	var nilUpdater *PriorityUpdater
	require.Error(t, nilUpdater.Update(1, false))
	require.Error(t, new(PriorityUpdater).Update(1, false))
	conn, _ := newConnPair(t)
	require.NoError(t, conn.CloseWithError(quic.ApplicationErrorCode(0), "done"))
	p := &PriorityUpdater{ready: true, request: context.Background(), connection: conn.Context()}
	require.Error(t, p.Update(1, false))
}
