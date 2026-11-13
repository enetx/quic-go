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

func newBatchHandler(t *testing.T) *sentPacketHandler {
	t.Helper()
	return NewSentPacketHandler(0, 1252, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger, ClientSendConfig{CoalescePTOProbes: true, InitialACKResetsPTO: true, RetainInitialCryptoProbes: true, RetainHandshakeCryptoProbes: true, StreamDataRecovery: true, InitialProbePackets: 2, HandshakeProbePackets: 2, ApplicationProbePackets: 2, DisablePacketNumberSkipping: true, SeparatePacketNumberSpaces: true}).(*sentPacketHandler)
}

func TestPTOBatchSharesDatagramAllowanceAcrossThreeSpaces(t *testing.T) {
	h := newBatchHandler(t)
	now := monotime.Now()
	lost := make([]int, 2)
	app := &probeStreamRecorder{useful: true}
	for i, level := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT} {
		pn := h.PopPacketNumber(level.PacketNumberSpace())
		var frames []Frame
		var streams []StreamFrame
		if i < 2 {
			index := i
			frames = []Frame{{Frame: &wire.CryptoFrame{Data: []byte("crypto")}, Handler: &customFrameHandler{onLost: func(wire.Frame) { lost[index]++ }}}}
		} else {
			streams = []StreamFrame{{Frame: &wire.StreamFrame{Data: []byte("early")}, Handler: app}}
		}
		h.SentPacket(now, pn, protocol.InvalidPacketNumber, streams, frames, level, protocol.ECNNon, 500, false, false)
	}
	deadline := h.GetLossDetectionTimeout()
	require.NoError(t, h.OnLossDetectionTimeout(deadline))
	require.EqualValues(t, 1, h.ptoCount)
	force, ok := BeginPTOProbeDatagram(h, 1252)
	require.True(t, ok)
	require.Equal(t, [3]bool{true, true, true}, force)
	require.Equal(t, []int{1, 1}, lost)
	require.Equal(t, 1, app.probed)
	require.Equal(t, 1, h.numProbesToSend)
	// Three protected packets consume just one UDP allowance. No second forced
	// Initial/Handshake PING is needed; Application can still elicit its ACK.
	for _, level := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption1RTT} {
		pn := h.PopPacketNumber(level.PacketNumberSpace())
		h.SentPacket(deadline, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, level, protocol.ECNNon, 100, false, false)
	}
	require.Equal(t, 1, h.numProbesToSend)
	force, ok = BeginPTOProbeDatagram(h, 1252)
	require.True(t, ok)
	require.Equal(t, [3]bool{false, false, true}, force)
	require.Zero(t, h.numProbesToSend)
	_, ok = BeginPTOProbeDatagram(h, 1252)
	require.False(t, ok)
}

func TestPTOBatchUsesOneByteBudgetForAllSpaces(t *testing.T) {
	h := newBatchHandler(t)
	now := monotime.Now()
	lost := 0
	app := &probeStreamRecorder{useful: true}
	for _, level := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT} {
		var frames []Frame
		var streams []StreamFrame
		if level == protocol.Encryption0RTT {
			streams = []StreamFrame{{Frame: &wire.StreamFrame{Data: []byte("early")}, Handler: app}}
		} else {
			frames = []Frame{{Frame: &wire.CryptoFrame{Data: []byte("crypto")}, Handler: &customFrameHandler{onLost: func(wire.Frame) { lost++ }}}}
		}
		h.SentPacket(now, h.PopPacketNumber(level.PacketNumberSpace()), protocol.InvalidPacketNumber, streams, frames, level, protocol.ECNNon, 1252, false, false)
	}
	require.NoError(t, h.OnLossDetectionTimeout(h.GetLossDetectionTimeout()))
	_, ok := BeginPTOProbeDatagram(h, 1252)
	require.True(t, ok)
	require.Equal(t, 2, lost)
	require.Zero(t, app.probed)
	require.EqualValues(t, 3756, h.bytesInFlight, "PTO selection must not declare congestion loss")
}

func TestPTOBatchLaterArmedSpaceForcesProbeWithoutEarlyRetransmission(t *testing.T) {
	h := newBatchHandler(t)
	now := monotime.Now()
	lost := [2]int{}
	for i, level := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake} {
		index := i
		h.SentPacket(now.Add(time.Duration(i)*time.Millisecond), h.PopPacketNumber(level.PacketNumberSpace()), protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.CryptoFrame{Data: []byte("crypto")}, Handler: &customFrameHandler{onLost: func(wire.Frame) { lost[index]++ }}}}, level, protocol.ECNNon, 500, false, false)
	}
	require.NoError(t, h.OnLossDetectionTimeout(h.GetLossDetectionTimeout()))
	force, ok := BeginPTOProbeDatagram(h, 1252)
	require.True(t, ok)
	require.Equal(t, [3]bool{true, true, false}, force)
	require.Equal(t, [2]int{1, 0}, lost)
}

func TestPTOBatchHandshakeTimeoutReleasesRecentInitialCrypto(t *testing.T) {
	h := newBatchHandler(t)
	now := monotime.Now()
	lost := [2]int{}
	for i, level := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake} {
		index := i
		sent := now
		if i == 0 {
			sent = sent.Add(time.Millisecond)
		}
		h.SentPacket(sent, h.PopPacketNumber(level.PacketNumberSpace()), protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.CryptoFrame{Data: []byte("crypto")}, Handler: &customFrameHandler{onLost: func(wire.Frame) { lost[index]++ }}}}, level, protocol.ECNNon, 500, false, false)
	}
	require.NoError(t, h.OnLossDetectionTimeout(h.GetLossDetectionTimeout()))
	_, ok := BeginPTOProbeDatagram(h, 1252)
	require.True(t, ok)
	require.Equal(t, [2]int{1, 1}, lost)
}

func TestPTOBatchCryptoACKOnlyBaselineAndKeyRetirement(t *testing.T) {
	h := newBatchHandler(t)
	now := monotime.Now()
	h.SentPacket(now, h.PopPacketNumber(protocol.PacketNumberSpaceInitial), 0, nil, nil, protocol.EncryptionInitial, protocol.ECNNon, 100, false, false)
	require.False(t, h.GetLossDetectionTimeout().IsZero())
	require.NoError(t, h.OnLossDetectionTimeout(h.GetLossDetectionTimeout()))
	_, ok := BeginPTOProbeDatagram(h, 1252)
	require.True(t, ok)
	h.DropPackets(protocol.EncryptionInitial, now)
	require.Nil(t, h.probeBatch)
	require.Zero(t, h.numProbesToSend)
}

func TestPTOBatchPrimesHandshakeOnlyWithKeysAndInitialACK(t *testing.T) {
	h := newBatchHandler(t)
	now := monotime.Now()
	h.initialPackets.lastAckElicitingPacketTime = now
	fired := now.Add(h.getScaledPTO(false))
	require.NoError(t, h.OnLossDetectionTimeout(fired))
	PrimePTOHandshake(h, true, fired)
	require.True(t, h.handshakePackets.lastAckElicitingPacketTime.IsZero())
	h = newBatchHandler(t)
	h.initialPackets.lastAckElicitingPacketTime = now
	h.initialPackets.largestAcked = 0
	require.NoError(t, h.OnLossDetectionTimeout(fired))
	PrimePTOHandshake(h, false, fired)
	require.True(t, h.handshakePackets.lastAckElicitingPacketTime.IsZero())
	PrimePTOHandshake(h, true, fired.Add(time.Millisecond))
	require.True(t, h.handshakePackets.lastAckElicitingPacketTime.IsZero(), "a different timer event must not prime Handshake")
	PrimePTOHandshake(h, true, fired)
	require.Equal(t, fired, h.handshakePackets.lastAckElicitingPacketTime)
	PrimePTOHandshake(h, true, fired.Add(time.Second))
	require.Equal(t, fired, h.handshakePackets.lastAckElicitingPacketTime)
}

func TestInitialACKBackoffResetIsIndependentOfProbeCoalescing(t *testing.T) {
	for _, reset := range []bool{false, true} {
		h := newBatchHandler(t)
		h.coalescePTOProbes = false
		h.initialACKResetsPTO = reset
		now := monotime.Now()
		pn := h.PopPacketNumber(protocol.PacketNumberSpaceInitial)
		h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionInitial, protocol.ECNNon, 100, false, false)
		h.ptoCount = 3
		_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.EncryptionInitial, now.Add(time.Millisecond))
		require.NoError(t, err)
		if reset {
			require.Zero(t, h.ptoCount)
		} else {
			require.EqualValues(t, 3, h.ptoCount)
		}
	}
}

func TestPTOBatchEarlyRejectionDoesNotDiscardCryptoBudget(t *testing.T) {
	h := newBatchHandler(t)
	now := monotime.Now()
	for _, level := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.Encryption0RTT} {
		h.SentPacket(now, h.PopPacketNumber(level.PacketNumberSpace()), protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, level, protocol.ECNNon, 100, false, false)
	}
	require.NoError(t, h.OnLossDetectionTimeout(h.GetLossDetectionTimeout()))
	_, ok := BeginPTOProbeDatagram(h, 1252)
	require.True(t, ok)
	h.DropPackets(protocol.Encryption0RTT, now)
	require.NotNil(t, h.probeBatch)
	require.EqualValues(t, 1, h.ptoCount)
	require.Equal(t, 1, h.numProbesToSend)
}

func TestPTOBatchHonorsConfiguredDatagramAllowance(t *testing.T) {
	for _, count := range []uint8{0, 1, 2} {
		h := newBatchHandler(t)
		h.initialProbePackets = count
		now := monotime.Now()
		h.SentPacket(now, h.PopPacketNumber(protocol.PacketNumberSpaceInitial), protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionInitial, protocol.ECNNon, 100, false, false)
		require.NoError(t, h.OnLossDetectionTimeout(h.GetLossDetectionTimeout()))
		want := int(count)
		if want == 0 {
			want = 2
		}
		for range want {
			_, ok := BeginPTOProbeDatagram(h, 1252)
			require.True(t, ok)
		}
		_, ok := BeginPTOProbeDatagram(h, 1252)
		require.False(t, ok)
	}
}

func TestPTOBatchRetryAndACKRetireUnusedDatagrams(t *testing.T) {
	for _, retry := range []bool{false, true} {
		h := newBatchHandler(t)
		now := monotime.Now()
		pn := h.PopPacketNumber(protocol.PacketNumberSpaceInitial)
		h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionInitial, protocol.ECNNon, 100, false, false)
		deadline := h.GetLossDetectionTimeout()
		require.NoError(t, h.OnLossDetectionTimeout(deadline))
		_, ok := BeginPTOProbeDatagram(h, 1252)
		require.True(t, ok)
		if retry {
			h.ResetForRetry(deadline.Add(time.Millisecond))
		} else {
			_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.EncryptionInitial, deadline.Add(time.Millisecond))
			require.NoError(t, err)
		}
		require.Nil(t, h.probeBatch)
		require.Zero(t, h.numProbesToSend)
		require.Zero(t, h.ptoCount)
		_, ok = BeginPTOProbeDatagram(h, 1252)
		require.False(t, ok)
	}
}
