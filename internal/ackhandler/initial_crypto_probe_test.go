package ackhandler

import (
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestInitialCryptoProbeAllowanceAndRealLateACK(t *testing.T) {
	for _, allowance := range []uint8{0, 1, 2} {
		h := NewSentPacketHandler(0, 1252, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger, ClientSendConfig{RetainInitialCryptoProbes: true, InitialProbePackets: allowance, InitialProbeSkipPacketNumber: allowance == 1}).(*sentPacketHandler)
		var acked, lost int
		pn := h.PopPacketNumber(protocol.PacketNumberSpaceInitial)
		now := monotime.Now()
		h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.CryptoFrame{Data: []byte("initial")}, Handler: &customFrameHandler{onLost: func(wire.Frame) { lost++ }, onAcked: func(wire.Frame) { acked++ }}}}, protocol.EncryptionInitial, protocol.ECNNon, 1252, false, false)
		deadline := h.GetLossDetectionTimeout()
		require.NoError(t, h.OnLossDetectionTimeout(deadline))
		want := int(allowance)
		if want == 0 {
			want = 2
		}
		require.Equal(t, want, h.numProbesToSend)
		if allowance == 1 {
			require.EqualValues(t, 2, h.PopPacketNumber(protocol.PacketNumberSpaceInitial))
		} else {
			require.EqualValues(t, 1, h.PopPacketNumber(protocol.PacketNumberSpaceInitial))
		}
		require.True(t, h.QueueProbePacket(protocol.PacketNumberSpaceInitial))
		require.Equal(t, 1, lost)
		_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.EncryptionInitial, deadline.Add(time.Millisecond))
		require.NoError(t, err)
		require.Equal(t, 1, acked, "the ACK of the original packet must reach the crypto range tracker")
		require.Zero(t, h.bytesInFlight)
	}
}

func TestInitialProbePolicyWhenOnlyPeerValidationRemains(t *testing.T) {
	for _, allowance := range []uint8{0, 1, 2} {
		h := NewSentPacketHandler(0, 1252, utils.NewRTTStats(), &utils.ConnectionStats{}, false, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger, ClientSendConfig{InitialProbePackets: allowance, InitialProbeSkipPacketNumber: allowance == 1}).(*sentPacketHandler)
		require.NoError(t, h.OnLossDetectionTimeout(monotime.Now()))
		want := int(allowance)
		if want == 0 {
			want = 1
		}
		require.Equal(t, want, h.numProbesToSend)
		next := h.PopPacketNumber(protocol.PacketNumberSpaceInitial)
		if allowance == 1 {
			require.EqualValues(t, 1, next)
		} else {
			require.Zero(t, next)
		}
	}
}

func TestInitialCryptoProbeKeepsOriginalAcknowledgment(t *testing.T) {
	h := &sentPacketHandler{retainInitialCryptoProbes: true, hist: *newSentPacketHistory()}
	var lost, acked int
	for pn := protocol.PacketNumber(1); pn <= 2; pn++ {
		frame := Frame{Frame: &wire.CryptoFrame{Offset: protocol.ByteCount(pn - 1), Data: []byte{byte(pn)}}, Handler: &customFrameHandler{onLost: func(wire.Frame) { lost++ }, onAcked: func(wire.Frame) { acked++ }}}
		p := &packet{Frames: []Frame{frame}, EncryptionLevel: protocol.EncryptionInitial, SendTime: monotime.Now()}
		h.hist.SentPacket(pn, p)
	}
	require.True(t, h.QueueProbePacket(protocol.PacketNumberSpaceInitial))
	require.True(t, h.QueueProbePacket(protocol.PacketNumberSpaceInitial))
	require.False(t, h.QueueProbePacket(protocol.PacketNumberSpaceInitial))
	require.Equal(t, 2, lost)
	// Unlike declaring these packets lost, PTO keeps their frame callbacks and
	// allows a later original ACK to retire an already scheduled retransmission.
	for _, p := range h.hist.Packets() {
		require.NotEmpty(t, p.Frames)
		for _, f := range p.Frames {
			f.Handler.OnAcked(f.Frame)
		}
	}
	require.Equal(t, 2, acked)
	require.EqualValues(t, 2, h.hist.numOutstanding)
}
