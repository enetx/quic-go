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

func TestPeerEarlyRecoveryDiscardsWithoutCongestionLoss(t *testing.T) {
	for _, separate := range []bool{false, true} {
		h := NewSentPacketHandler(0, 1252, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger, ClientSendConfig{SeparatePacketNumberSpaces: separate, StreamDataRecovery: true, DisablePacketNumberSkipping: true}).(*sentPacketHandler)
		now := monotime.Now()
		cryptoLost, controlLost := 0, 0
		h.SentPacket(now, h.PopPacketNumber(protocol.PacketNumberSpaceInitial), protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.CryptoFrame{Data: []byte("hello")}, Handler: &customFrameHandler{onLost: func(wire.Frame) { cryptoLost++ }}}}, protocol.EncryptionInitial, protocol.ECNNon, 1252, false, false)
		stream := &probeStreamRecorder{useful: true}
		pn := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
		h.SentPacket(now, pn, protocol.InvalidPacketNumber, []StreamFrame{{Frame: &wire.StreamFrame{Data: []byte("early"), Fin: true}, Handler: stream}}, []Frame{{Frame: &wire.MaxDataFrame{}, Handler: &customFrameHandler{onLost: func(wire.Frame) { controlLost++ }}}}, protocol.Encryption0RTT, protocol.ECNNon, 100, false, false)
		// A later 1-RTT packet is not part of the early hint scope.
		oneRTT := &probeStreamRecorder{useful: true}
		later := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
		h.SentPacket(now, later, protocol.InvalidPacketNumber, []StreamFrame{{Frame: &wire.StreamFrame{Data: []byte("later")}, Handler: oneRTT}}, nil, protocol.Encryption1RTT, protocol.ECNNon, 200, false, false)
		h.ptoCount, h.numProbesToSend = 2, 1
		h.probeBatch = &ptoProbeBatch{force: [3]bool{true, false, true}}
		h.setLossDetectionTimer(now)
		window, alarm := h.congestion.GetCongestionWindow(), h.GetLossDetectionTimeout()
		ResendEarlyData(h, now.Add(time.Millisecond))
		require.Equal(t, 1, stream.lost)
		require.Equal(t, 1, controlLost)
		require.Zero(t, cryptoLost)
		require.Zero(t, oneRTT.lost)
		require.EqualValues(t, 1452, h.bytesInFlight)
		require.Equal(t, 1, h.appDataPackets.numOutstanding)
		require.Equal(t, window, h.congestion.GetCongestionWindow())
		require.EqualValues(t, 2, h.ptoCount)
		require.Equal(t, 1, h.numProbesToSend)
		require.NotNil(t, h.probeBatch)
		require.Equal(t, alarm, h.GetLossDetectionTimeout())
		ResendEarlyData(h, now.Add(2*time.Millisecond))
		require.Equal(t, 1, stream.lost)
		_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.Encryption1RTT, now.Add(3*time.Millisecond))
		require.NoError(t, err)
		require.Zero(t, stream.acked, "discarded originals no longer own recovery tokens")
		require.EqualValues(t, 1452, h.bytesInFlight)
	}
}

func TestPeerEarlyRecoveryStopsAtFirstApplicationACK(t *testing.T) {
	for _, acknowledged := range []protocol.EncryptionLevel{protocol.Encryption0RTT, protocol.Encryption1RTT} {
		h := newBatchHandler(t)
		now := monotime.Now()
		pn := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
		h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, acknowledged, protocol.ECNNon, 100, false, false)
		_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.Encryption1RTT, now.Add(time.Millisecond))
		require.NoError(t, err)
		r := &probeStreamRecorder{useful: true}
		h.SentPacket(now.Add(2*time.Millisecond), h.PopPacketNumber(protocol.PacketNumberSpaceAppData), protocol.InvalidPacketNumber, []StreamFrame{{Frame: &wire.StreamFrame{Data: []byte("pending")}, Handler: r}}, nil, protocol.Encryption0RTT, protocol.ECNNon, 200, false, false)
		ResendEarlyData(h, now.Add(3*time.Millisecond))
		require.Zero(t, r.lost)
		require.EqualValues(t, 200, h.bytesInFlight)
	}
}

func TestPeerEarlyRecoveryDropsRetainedEarlyMetadataOnly(t *testing.T) {
	h := newBatchHandler(t)
	now := monotime.Now()
	r := &probeStreamRecorder{useful: true}
	h.retainedStreamPackets = []retainedStreamPacket{{level: protocol.Encryption0RTT}, {level: protocol.Encryption1RTT, lossTime: now, handlers: []FrameHandler{r}}}
	ResendEarlyData(h, now)
	require.Len(t, h.retainedStreamPackets, 1)
	require.Equal(t, protocol.Encryption1RTT, h.retainedStreamPackets[0].level)
	ResendEarlyData(nil, now)
}

func TestPeerEarlyRecoveryStopsAfterRetainedLossACK(t *testing.T) {
	h := newBatchHandler(t)
	now := monotime.Now()
	r := &probeStreamRecorder{useful: true}
	pn := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
	h.SentPacket(now, pn, protocol.InvalidPacketNumber, []StreamFrame{{Frame: &wire.StreamFrame{Data: []byte("early")}, Handler: r}}, nil, protocol.Encryption0RTT, protocol.ECNNon, 100, false, false)
	p := h.history(protocol.PacketNumberSpaceAppData).packets[0]
	h.retainStreamPacket(pn, p, now)
	h.removeFromBytesInFlight(p)
	require.NoError(t, h.history(protocol.PacketNumberSpaceAppData).Remove(pn))
	pending := &probeStreamRecorder{useful: true}
	h.SentPacket(now, h.PopPacketNumber(protocol.PacketNumberSpaceAppData), protocol.InvalidPacketNumber, []StreamFrame{{Frame: &wire.StreamFrame{Data: []byte("pending")}, Handler: pending}}, nil, protocol.Encryption0RTT, protocol.ECNNon, 100, false, false)
	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.Encryption1RTT, now.Add(time.Millisecond))
	require.NoError(t, err)
	require.True(t, h.earlyDataAcked)
	ResendEarlyData(h, now.Add(2*time.Millisecond))
	require.Zero(t, pending.lost)
	h.ResetForRetry(now.Add(3 * time.Millisecond))
	require.False(t, h.earlyDataAcked)
}
