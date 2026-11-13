package quic

import (
	"context"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/enetx/quic-go/internal/ackhandler"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func recoverySendStream(t *testing.T, data string, fin bool) (*SendStream, ackhandler.StreamFrame, *MockStreamSender) {
	t.Helper()
	sender := NewMockStreamSender(gomock.NewController(t))
	sender.EXPECT().onHasStreamData(gomock.Any(), gomock.Any()).AnyTimes()
	sender.EXPECT().onHasStreamRetransmission(gomock.Any(), gomock.Any()).AnyTimes()
	sender.EXPECT().onHasStreamControlFrame(gomock.Any(), gomock.Any()).AnyTimes()
	stream := newSendStream(t.Context(), 0, sender, newTestStreamFlowControllerWithSendWindow(0, protocol.MaxByteCount), false)
	stream.recovery = &streamRangeRecovery{}
	require.NoError(t, stream.TryWriteAll([]byte(data)))
	if fin {
		require.NoError(t, stream.Close())
	}
	frame, _, _ := stream.popStreamFrame(1200, protocol.Version1)
	require.NotNil(t, frame.Frame)
	return stream, frame, sender
}

func TestStreamRangeOriginalACKRetiresSplitCopies(t *testing.T) {
	s, original, sender := recoverySendStream(t, strings.Repeat("a", 100), true)
	sender.EXPECT().onStreamCompleted(protocol.StreamID(0)).Times(1)
	require.True(t, original.Handler.(*streamRangeFrame).OnProbe(original.Frame))
	a, more := s.popRetransmissionFrame(40, protocol.Version1)
	require.True(t, more)
	b, _ := s.popRetransmissionFrame(1200, protocol.Version1)
	require.EqualValues(t, 3, s.numOutstandingFrames)
	original.Handler.OnAcked(original.Frame)
	require.Zero(t, s.numOutstandingFrames)
	require.Empty(t, s.retransmissionQueue)
	// A copy's later loss/ACK cannot resurrect acknowledged data or complete twice.
	a.Handler.OnLost(a.Frame)
	b.Handler.OnAcked(b.Frame)
	original.Handler.OnAcked(nil)
	require.Empty(t, s.retransmissionQueue)
	require.Zero(t, s.numOutstandingFrames)
}

func TestStreamRangePartialCopyACKAndLateLostOriginal(t *testing.T) {
	s, original, sender := recoverySendStream(t, strings.Repeat("b", 100), true)
	sender.EXPECT().onStreamCompleted(protocol.StreamID(0)).Times(1)
	require.True(t, original.Handler.(*streamRangeFrame).OnProbe(original.Frame))
	first, more := s.popRetransmissionFrame(40, protocol.Version1)
	require.True(t, more)
	acknowledged := first.Frame.DataLen()
	first.Handler.OnAcked(first.Frame)
	original.Handler.OnLost(original.Frame)
	require.Len(t, s.retransmissionQueue, 1)
	require.Equal(t, acknowledged, s.retransmissionQueue[0].Offset)
	require.EqualValues(t, 100-acknowledged, s.retransmissionQueue[0].DataLen())
	// Real-loss metadata no longer owns the pooled frame, but a late ACK still
	// covers the original byte range and FIN, retiring the queued suffix.
	original.Handler.OnAcked(nil)
	require.Empty(t, s.retransmissionQueue)
	require.True(t, s.completed)
	require.Zero(t, s.numOutstandingFrames)
}

func TestStreamRangeFINOnlyAndRepeatedLoss(t *testing.T) {
	s, original, sender := recoverySendStream(t, "", true)
	sender.EXPECT().onStreamCompleted(protocol.StreamID(0)).Times(1)
	original.Handler.OnLost(original.Frame)
	original.Handler.OnLost(nil)
	require.Len(t, s.retransmissionQueue, 1)
	copy, _ := s.popRetransmissionFrame(1200, protocol.Version1)
	require.True(t, copy.Frame.Fin)
	require.Empty(t, copy.Frame.Data)
	copy.Handler.OnAcked(copy.Frame)
	original.Handler.OnAcked(nil)
	require.Zero(t, s.numOutstandingFrames)
	require.Empty(t, s.retransmissionQueue)
}

func TestStreamRangeCancellationAndEpochShutdown(t *testing.T) {
	for _, mode := range []string{"cancel", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			s, original, _ := recoverySendStream(t, "early data", false)
			require.True(t, original.Handler.(*streamRangeFrame).OnProbe(original.Frame))
			if mode == "cancel" {
				s.CancelWrite(42)
			} else {
				s.closeForShutdown(Err0RTTRejected)
			}
			original.Handler.OnAcked(original.Frame)
			original.Handler.OnLost(nil)
			require.Empty(t, s.retransmissionQueue)
			require.False(t, original.Handler.(*streamRangeFrame).HasOutstandingData())
		})
	}
}

func TestStreamRangeLargeOffsetsAndReliableReset(t *testing.T) {
	sender := NewMockStreamSender(gomock.NewController(t))
	sender.EXPECT().onHasStreamData(gomock.Any(), gomock.Any()).AnyTimes()
	sender.EXPECT().onHasStreamControlFrame(gomock.Any(), gomock.Any()).AnyTimes()
	sender.EXPECT().onHasStreamRetransmission(gomock.Any(), gomock.Any()).AnyTimes()
	s := newSendStream(context.Background(), 0, sender, newTestStreamFlowControllerWithSendWindow(0, protocol.MaxByteCount), true)
	s.recovery = &streamRangeRecovery{}
	const offset protocol.ByteCount = 1 << 40
	s.writeOffset = offset
	require.NoError(t, s.TryWriteAll([]byte("1234567890")))
	s.reliableSize = offset + 5
	frame, _, _ := s.popStreamFrame(1200, protocol.Version1)
	require.Equal(t, offset, frame.Frame.Offset)
	s.CancelWrite(42)
	frame.Handler.OnLost(frame.Frame)
	require.Len(t, s.retransmissionQueue, 1)
	require.Equal(t, "12345", string(s.retransmissionQueue[0].Data))
	require.False(t, s.retransmissionQueue[0].Fin)
	frame.Handler.OnAcked(nil)
	require.Empty(t, s.retransmissionQueue)
	require.Zero(t, s.numOutstandingFrames)
}

func TestStreamRangeOverlappingProbeQueueIsCoalesced(t *testing.T) {
	s, original, _ := recoverySendStream(t, "abcdefghij", false)
	h := original.Handler.(*streamRangeFrame)
	require.True(t, h.OnProbe(original.Frame))
	require.False(t, h.OnProbe(original.Frame))
	copy, _ := s.popRetransmissionFrame(6, protocol.Version1)
	require.NotNil(t, copy.Frame)
	require.True(t, h.OnProbe(original.Frame)) // only the already transmitted prefix
	require.Len(t, s.retransmissionQueue, 1)
	require.Zero(t, s.retransmissionQueue[0].Offset)
	require.Equal(t, "abcdefghij", string(s.retransmissionQueue[0].Data))
	original.Handler.OnAcked(original.Frame)
	require.Empty(t, s.retransmissionQueue)
	copy.Handler.OnLost(copy.Frame)
	require.Zero(t, s.numOutstandingFrames)
}

func TestStreamRangeRecoveryAgainstByteModel(t *testing.T) {
	for seed := uint64(1); seed <= 8; seed++ {
		payload := make([]byte, 100)
		for i := range payload {
			payload[i] = byte('a' + i%26)
		}
		s, original, sender := recoverySendStream(t, string(payload), true)
		completed := 0
		sender.EXPECT().onStreamCompleted(protocol.StreamID(0)).AnyTimes().Do(func(protocol.StreamID) { completed++ })
		transmissions := []*streamRangeFrame{original.Handler.(*streamRangeFrame)}
		acknowledged := make([]bool, len(payload))
		finAcked := false
		random := rand.New(rand.NewPCG(seed, 31))
		for step := 0; step < 250; step++ {
			f := transmissions[random.IntN(len(transmissions))]
			switch random.IntN(4) {
			case 0:
				f.OnAcked(nil)
				for i := int(f.part.start); i < int(f.part.end); i++ {
					acknowledged[i] = true
				}
				finAcked = finAcked || f.fin
			case 1:
				f.OnLost(nil)
			case 2:
				f.OnProbe(nil)
			case 3:
				next, _ := s.popRetransmissionFrame(protocol.ByteCount(6+random.IntN(50)), protocol.Version1)
				if next.Frame != nil {
					transmissions = append(transmissions, next.Handler.(*streamRangeFrame))
				}
			}
			queued := make([]bool, len(payload))
			queuedFIN := false
			for _, q := range s.retransmissionQueue {
				require.Equal(t, payload[q.Offset:q.Offset+q.DataLen()], q.Data)
				for i := int(q.Offset); i < int(q.Offset+q.DataLen()); i++ {
					require.False(t, acknowledged[i], "acknowledged byte queued again")
					require.False(t, queued[i], "byte queued more than once")
					queued[i] = true
				}
				if q.Fin {
					require.False(t, finAcked)
					require.False(t, queuedFIN)
					queuedFIN = true
				}
			}
			require.EqualValues(t, len(s.recovery.live), s.numOutstandingFrames)
			require.LessOrEqual(t, completed, 1)
		}
		original.Handler.OnAcked(nil)
		for _, f := range transmissions {
			f.OnLost(nil)
		}
		require.Empty(t, s.retransmissionQueue)
		require.Zero(t, s.numOutstandingFrames)
		require.Equal(t, 1, completed)
	}
}
