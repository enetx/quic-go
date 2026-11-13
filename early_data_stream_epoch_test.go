package quic

import (
	"context"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/qerr"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestRejectedEarlyStreamFINCannotResetReusedID(t *testing.T) {
	sender := NewMockStreamSender(gomock.NewController(t))
	stream := newSendStream(context.Background(), 0, sender, newTestStreamFlowControllerWithSendWindow(42, protocol.MaxByteCount), false)
	sender.EXPECT().onHasStreamData(protocol.StreamID(0), stream)
	require.NoError(t, stream.Close())
	stream.closeForShutdown(Err0RTTRejected)
	// No sender callback may escape from this retired epoch, including after FIN.
	stream.CancelWrite(123)
	stream.handleStopSendingFrame(&wire.StopSendingFrame{StreamID: 0, ErrorCode: qerr.StreamErrorCode(123)})
	_, has, more := stream.getControlFrame(monotime.Now())
	require.False(t, has)
	require.False(t, more)
	_, err := stream.Write([]byte("late"))
	require.ErrorIs(t, err, Err0RTTRejected)
}

func TestRejectedEpochCannotCompleteReplacementStream(t *testing.T) {
	sender := NewMockStreamSender(gomock.NewController(t))
	epoch := &streamEpochSender{streamSender: sender}
	m := newStreamsMap(context.Background(), epoch, func(wire.Frame) {}, newTestStreamFlowController, 1, 1, false, protocol.PerspectiveClient)
	parameters := &wire.TransportParameters{MaxBidiStreamNum: 10, MaxUniStreamNum: 10}
	m.HandleTransportParameters(parameters)
	old, err := m.OpenStream()
	require.NoError(t, err)
	m.ResetFor0RTT()
	m.HandleTransportParameters(parameters)
	m.UseResetMaps()
	fresh, err := m.OpenStream()
	require.NoError(t, err)
	require.Equal(t, old.StreamID(), fresh.StreamID())
	// These callbacks can have been delayed by an application goroutine. None may
	// reach the connection, which would otherwise delete or reactivate stream 0.
	epoch.onStreamCompleted(0)
	epoch.onStreamCreditReleased(0)
	epoch.onHasStreamData(0, old.sendStr)
	epoch.onHasStreamRetransmission(0, old.sendStr)
	epoch.onHasStreamControlFrame(0, old)
	epoch.onHasConnectionData()
	epoch.updateStreamPriority(0)
	epoch.recordStreamPriorityUpdated(0, 1, true)
	got, err := m.getSendStream(0)
	require.NoError(t, err)
	require.Same(t, fresh, got)
	sender.EXPECT().onHasStreamData(protocol.StreamID(0), fresh.sendStr)
	m.sender.onHasStreamData(0, fresh.sendStr)
}

func TestRejectedEpochDrainsCallbackBeforeMapReplacement(t *testing.T) {
	sender := NewMockStreamSender(gomock.NewController(t))
	epoch := &streamEpochSender{streamSender: sender}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	sender.EXPECT().onStreamCompleted(protocol.StreamID(0)).Do(func(protocol.StreamID) {
		close(entered)
		<-release
	})
	go func() { epoch.onStreamCompleted(0); close(finished) }()
	<-entered
	retired := make(chan struct{})
	go func() { epoch.retire(); close(retired) }()
	select {
	case <-retired:
		t.Fatal("retired before the in-flight callback finished")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	<-finished
	<-retired
	epoch.onStreamCompleted(0)
}
