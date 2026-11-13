package http3

import (
	"testing"

	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func TestQPACKResumedSettingsDoNotRepeatCapacityOrResetTable(t *testing.T) {
	conn, _ := newConnPair(t)
	// Hold the writer; inspect complete queued instructions before network I/O.
	q := newClientQPACK(&rawConn{conn: conn}, &QPACKConfig{DynamicTable: true, EncoderTableCapacity: 4096}, make(chan struct{}), 8)
	q.encoder.reserved.Store(true)
	require.NoError(t, q.onSettings(4096, 16, true))
	require.Equal(t, []byte{0x3f, 0xe1, 0x1f}, <-q.encoder.queue)
	block, err := q.encode(0, []base.HeaderField{{Name: "x-early", Value: "insert-once"}})
	require.NoError(t, err)
	require.NotZero(t, block[0])
	require.NotEmpty(t, <-q.encoder.queue)
	for _, blocked := range []uint64{16, 32} {
		require.NoError(t, q.onSettings(4096, blocked, true))
		require.Empty(t, q.encoder.queue, "the actual SETTINGS must not repeat the remembered capacity")
		block, err = q.encode(4, []base.HeaderField{{Name: "x-early", Value: "insert-once"}})
		require.NoError(t, err)
		require.NotZero(t, block[0])
		require.Empty(t, q.encoder.queue, "compatible SETTINGS must retain the existing entry")
	}
}

func TestQPACKResumedDefaultCanEnableCapacity(t *testing.T) {
	conn, _ := newConnPair(t)
	q := newClientQPACK(&rawConn{conn: conn}, &QPACKConfig{DynamicTable: true, EncoderTableCapacity: 4096}, make(chan struct{}), 8)
	q.encoder.reserved.Store(true)
	require.NoError(t, q.onSettings(0, 0, false))
	block, err := q.encode(0, []base.HeaderField{{Name: "x-early", Value: "literal"}})
	require.NoError(t, err)
	require.Zero(t, block[0])
	require.Empty(t, q.encoder.queue)
	require.NoError(t, q.onSettings(4096, 16, true))
	require.Equal(t, []byte{0x3f, 0xe1, 0x1f}, <-q.encoder.queue)
	block, err = q.encode(4, []base.HeaderField{{Name: "x-early", Value: "literal"}})
	require.NoError(t, err)
	require.NotZero(t, block[0])
	require.NotEmpty(t, <-q.encoder.queue)
}
