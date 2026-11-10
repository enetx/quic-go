package quic

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestPeerAckFrequencyFrameBudgetAndNeqoVector(t *testing.T) {
	var observed PeerAckFrequencyInfo
	s := newPeerAckFrequencySender(func(info PeerAckFrequencyInfo) (PeerAckFrequency, bool) {
		observed = info
		return PeerAckFrequency{AckElicitingThreshold: 5, MaxAckDelay: 2 * time.Millisecond}, true
	}, time.Millisecond, 25*time.Millisecond)
	require.NoError(t, s.refresh(24000, 1200, 8*time.Millisecond))
	require.EqualValues(t, 24000, observed.CongestionWindow)
	require.EqualValues(t, 1200, observed.MaxDatagramSize)
	require.Equal(t, 8*time.Millisecond, observed.SmoothedRTT)
	require.Equal(t, PeerAckFrequency{AckElicitingThreshold: 2, MaxAckDelay: 25 * time.Millisecond}, observed.Current)
	require.Nil(t, s.popFrame(6, protocol.Version1).Frame)
	require.Zero(t, s.nextSequence, "insufficient packet budget must not consume a sequence")
	frame := s.popFrame(7, protocol.Version1)
	require.NotNil(t, frame.Frame)
	encoded, err := frame.Frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	// Independent Neqo AckRate::write_frame values: sequence=0, tolerance=5,
	// delay=2000us, ignore_order=false. The legacy final field is one byte.
	// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/ackrate.rs
	require.Equal(t, "40af000547d000", hex.EncodeToString(encoded))
	require.Nil(t, s.popFrame(1200, protocol.Version1).Frame, "only one request may be outstanding")
	frame.Handler.OnAcked(frame.Frame)
	require.False(t, s.pending(), "acknowledging the target must not enqueue an identical update")
}

func TestPeerAckFrequencyLossAndLateAcknowledgment(t *testing.T) {
	target := PeerAckFrequency{AckElicitingThreshold: 10, MaxAckDelay: 50 * time.Millisecond, IgnoreOrder: true}
	s := newPeerAckFrequencySender(func(PeerAckFrequencyInfo) (PeerAckFrequency, bool) { return target, true },
		time.Millisecond, 25*time.Millisecond)
	require.NoError(t, s.refresh(24000, 1200, time.Millisecond))
	first := s.popFrame(1200, protocol.Version1)
	require.Equal(t, 50*time.Millisecond, s.effectiveDelay())
	target = PeerAckFrequency{AckElicitingThreshold: 2, MaxAckDelay: 2 * time.Millisecond}
	require.NoError(t, s.refresh(12000, 1200, time.Millisecond))
	require.False(t, s.pending())
	first.Handler.OnLost(first.Frame)
	require.True(t, s.pending())
	second := s.popFrame(1200, protocol.Version1)
	require.EqualValues(t, 1, second.Frame.(*wire.LegacyAckFrequencyFrame).SequenceNumber)
	require.EqualValues(t, 2, second.Frame.(*wire.LegacyAckFrequencyFrame).AckElicitingThreshold)
	require.Equal(t, 50*time.Millisecond, s.effectiveDelay(), "lost requests can have reached the peer")
	first.Handler.OnLost(first.Frame)
	first.Handler.OnAcked(first.Frame)
	require.NotNil(t, s.outstanding, "late feedback must not clear a newer request")
	second.Handler.OnAcked(second.Frame)
	require.Equal(t, target, s.current)
	require.Equal(t, 2*time.Millisecond, s.effectiveDelay())
	first.Handler.OnAcked(first.Frame)
	require.Equal(t, target, s.current, "stale ACK must not restore old settings")
	require.False(t, s.pending())
}

func TestPeerAckFrequencyRejectsInvalidTargets(t *testing.T) {
	for _, target := range []PeerAckFrequency{
		{MaxAckDelay: time.Millisecond},
		{AckElicitingThreshold: quicvarint.Max + 1, MaxAckDelay: time.Millisecond},
		{AckElicitingThreshold: 2, MaxAckDelay: -time.Millisecond},
		{AckElicitingThreshold: 2, MaxAckDelay: time.Microsecond},
		{AckElicitingThreshold: 2, MaxAckDelay: time.Millisecond + time.Nanosecond},
		{AckElicitingThreshold: 2, MaxAckDelay: protocol.MaxMaxAckDelay + time.Millisecond},
	} {
		s := newPeerAckFrequencySender(func(PeerAckFrequencyInfo) (PeerAckFrequency, bool) { return target, false },
			time.Millisecond, 25*time.Millisecond)
		require.ErrorContains(t, s.refresh(12000, 1200, time.Millisecond), "policy result")
		require.False(t, s.pending())
	}
}

func TestPeerAckFrequencySequenceExhaustion(t *testing.T) {
	s := newPeerAckFrequencySender(func(PeerAckFrequencyInfo) (PeerAckFrequency, bool) {
		return PeerAckFrequency{AckElicitingThreshold: 2, MaxAckDelay: time.Millisecond}, true
	}, time.Millisecond, 25*time.Millisecond)
	require.NoError(t, s.refresh(12000, 1200, time.Millisecond))
	s.nextSequence = quicvarint.Max
	frame := s.popFrame(1200, protocol.Version1)
	require.Equal(t, uint64(quicvarint.Max), frame.Frame.(*wire.LegacyAckFrequencyFrame).SequenceNumber)
	frame.Handler.OnLost(frame.Frame)
	require.Nil(t, s.popFrame(1200, protocol.Version1).Frame)
}

func TestPeerAckFrequencyFramerPreservesDeliveryHandler(t *testing.T) {
	s := newPeerAckFrequencySender(func(PeerAckFrequencyInfo) (PeerAckFrequency, bool) {
		return PeerAckFrequency{AckElicitingThreshold: 5, MaxAckDelay: time.Millisecond}, true
	}, time.Millisecond, 25*time.Millisecond)
	require.NoError(t, s.refresh(12000, 1200, time.Millisecond))
	f := newFramer(nil)
	f.peerAckFrequency = s
	f.QueueControlFrame(&wire.PathResponseFrame{})
	require.True(t, f.HasData())
	frames, length := f.AppendControlFrames(nil, 7, monotime.Now(), protocol.Version1)
	require.Len(t, frames, 1)
	require.LessOrEqual(t, length, protocol.ByteCount(7))
	require.NotNil(t, frames[0].Handler, "ACK/loss must bypass generic same-frame retransmission")
	frames[0].Handler.OnLost(frames[0].Frame)
	frames, length = f.AppendControlFrames(nil, 1200, monotime.Now(), protocol.Version1)
	require.Len(t, frames, 2)
	require.EqualValues(t, 1, frames[0].Frame.(*wire.LegacyAckFrequencyFrame).SequenceNumber)
	require.LessOrEqual(t, length, protocol.ByteCount(1200))
}
