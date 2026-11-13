package quic

import (
	"bytes"
	"testing"

	"github.com/enetx/quic-go/internal/ackhandler"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func creationTestStreams(t *testing.T, uniCredit protocol.ByteCount) (*framer, *SendStream, *Stream) {
	t.Helper()
	tc := newClientTestConnection(t, nil, &Config{ClientHandshake: &ClientHandshake{StreamSchedulingByCreation: true}}, true)
	tc.conn.restoreTransportParameters(&wire.TransportParameters{ActiveConnectionIDLimit: 2, InitialMaxData: 8192, InitialMaxStreamDataUni: uniCredit, InitialMaxStreamDataBidiRemote: 4096, MaxUniStreamNum: 3, MaxBidiStreamNum: 3})
	control, err := tc.conn.OpenUniStream()
	require.NoError(t, err)
	request, err := tc.conn.OpenStream()
	require.NoError(t, err)
	require.EqualValues(t, 2, control.StreamID())
	require.EqualValues(t, 0, request.StreamID())
	// Reversed publication order and a stronger local request priority cannot
	// reorder a stream created later in this explicit scheduling mode.
	request.SetPriority(0, false)
	require.NoError(t, request.sendStr.TryWriteAll(bytes.Repeat([]byte("R"), 100)))
	_, err = control.Write(bytes.Repeat([]byte("C"), 100))
	require.NoError(t, err)
	return tc.conn.framer, control, request
}

func creationAppend(f *framer, budget protocol.ByteCount) []ackhandler.StreamFrame {
	_, streams, _ := f.appendStreamFrames(nil, nil, budget, 1, protocol.Version1)
	return streams
}

func TestCreationSchedulingRetainsAnIdleStreamAndReleasesCompletedState(t *testing.T) {
	f, control, request := creationTestStreams(t, 4096)
	first := creationAppend(f, 12)
	require.Len(t, first, 1)
	require.Equal(t, control.StreamID(), first[0].Frame.StreamID)
	next := creationAppend(f, 1200)
	require.Len(t, next, 2)
	require.Equal(t, control.StreamID(), next[0].Frame.StreamID)
	require.Equal(t, request.StreamID(), next[1].Frame.StreamID)
	require.False(t, f.HasData())
	require.Len(t, f.creationOrder.entries, 2, "quiescent open streams keep their original order")
	require.NoError(t, request.sendStr.TryWriteAll([]byte("later request")))
	require.NoError(t, control.TryWriteAll([]byte("later control")))
	late := creationAppend(f, 1200)
	require.Len(t, late, 2)
	require.Equal(t, control.StreamID(), late[0].Frame.StreamID)
	f.RemoveActiveStream(control.StreamID())
	require.Len(t, f.creationOrder.entries, 1)
	f.RemoveActiveStream(request.StreamID())
	require.Empty(t, f.creationOrder.entries)
	require.Zero(t, f.creationOrder.ids.Len())
}

func TestCreationSchedulingSkipsCreditBlockedStreamsAndPreservesTheirPlace(t *testing.T) {
	f, control, request := creationTestStreams(t, 0)
	first := creationAppend(f, 50)
	require.NotEmpty(t, first)
	require.Equal(t, request.StreamID(), first[0].Frame.StreamID)
	control.updateSendWindow(4096)
	next := creationAppend(f, 1200)
	require.Len(t, next, 2)
	require.Equal(t, control.StreamID(), next[0].Frame.StreamID)
	require.Equal(t, request.StreamID(), next[1].Frame.StreamID)
}

func TestCreationSchedulingOrdersLostRangesAndClearsRejectedEarlyState(t *testing.T) {
	f, control, request := creationTestStreams(t, 4096)
	frames := creationAppend(f, 1200)
	require.Len(t, frames, 2)
	for i := len(frames) - 1; i >= 0; i-- {
		require.NotNil(t, frames[i].Handler)
		frames[i].Handler.OnLost(frames[i].Frame)
	}
	require.True(t, f.HasData())
	lost := creationAppend(f, 12)
	require.Len(t, lost, 1)
	require.Equal(t, control.StreamID(), lost[0].Frame.StreamID, "loss notification order must not reorder streams")
	// New request data remains behind retained lost ranges.
	require.NoError(t, request.sendStr.TryWriteAll([]byte("new bytes")))
	next := creationAppend(f, 1200)
	require.GreaterOrEqual(t, len(next), 2)
	require.Equal(t, control.StreamID(), next[0].Frame.StreamID)
	f.Handle0RTTRejection()
	require.False(t, f.HasData())
	require.Empty(t, f.creationOrder.entries)
	require.Zero(t, f.creationOrder.ids.Len())
	f.recordStreamCreation(0)
	require.Len(t, f.creationOrder.entries, 1, "reused stream IDs must receive fresh ordering state")
}
