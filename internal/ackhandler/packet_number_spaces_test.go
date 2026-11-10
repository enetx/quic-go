package ackhandler

import (
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/mocks"
	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/qerr"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func separateHandler(t *testing.T) *sentPacketHandler {
	t.Helper()
	return NewSentPacketHandler(37, 1257, utils.NewRTTStats(), new(utils.ConnectionStats), false, false, nil,
		protocol.PerspectiveClient, nil, utils.DefaultLogger, ClientSendConfig{SeparatePacketNumberSpaces: true}).(*sentPacketHandler)
}

func sendInSpace(h *sentPacketHandler, now monotime.Time, level protocol.EncryptionLevel, tracker *packetTracker) protocol.PacketNumber {
	pn := h.PopPacketNumber(level.PacketNumberSpace())
	h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{tracker.NewPingFrame(pn)}, level, protocol.ECNNon, 1257, false, false)
	return pn
}

func TestSeparateSpacesWireNumbersAndCongestionOrder(t *testing.T) {
	h := separateHandler(t)
	cc := mocks.NewMockSendAlgorithmWithDebugInfos(gomock.NewController(t))
	h.congestion = cc
	cc.EXPECT().MaybeExitSlowStart().AnyTimes()
	now := monotime.Now()
	var tracker packetTracker
	levels := []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT, protocol.Encryption1RTT, protocol.EncryptionInitial}
	wireNumbers := []protocol.PacketNumber{37, 0, 0, 1, 38}
	for i, level := range levels {
		cc.EXPECT().OnPacketSent(now, protocol.ByteCount(i*1257), protocol.PacketNumber(i), protocol.ByteCount(1257), true)
		require.Equal(t, wireNumbers[i], sendInSpace(h, now, level, &tracker))
	}
	// Overlapping wire PNs must acknowledge only the specified space, while
	// congestion receives the original globally ordered transmission identity.
	for _, i := range []int{3, 1, 4, 2, 0} {
		level := levels[i]
		if level == protocol.Encryption0RTT {
			level = protocol.Encryption1RTT
		}
		prior := h.bytesInFlight
		cc.EXPECT().OnPacketAcked(protocol.PacketNumber(i), protocol.ByteCount(1257), prior, gomock.Any())
		_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(wireNumbers[i])}, level, now.Add(time.Millisecond))
		require.NoError(t, err)
	}
	require.Zero(t, h.bytesInFlight)
	_, outstanding := h.trackedPackets()
	require.Zero(t, outstanding)
}

func TestSeparateSpacesRejectsUnsentAndSkippedACK(t *testing.T) {
	h := separateHandler(t)
	now := monotime.Now()
	var tracker packetTracker
	sendInSpace(h, now, protocol.EncryptionInitial, &tracker)
	sendInSpace(h, now, protocol.EncryptionHandshake, &tracker)
	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(37)}, protocol.EncryptionHandshake, now.Add(time.Millisecond))
	var transport *qerr.TransportError
	require.ErrorAs(t, err, &transport)
	require.Equal(t, qerr.ProtocolViolation, transport.ErrorCode)
	h.packetNumbers(protocol.PacketNumberSpaceAppData).packetsUntilSkip = 0
	pn := sendInSpace(h, now, protocol.Encryption1RTT, &tracker)
	require.EqualValues(t, 1, pn)
	_, err = h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(0, 1)}, protocol.Encryption1RTT, now.Add(time.Millisecond))
	require.ErrorAs(t, err, &transport)
	require.Equal(t, qerr.ProtocolViolation, transport.ErrorCode)
}

func TestSeparateSpacesRetryDropAndMigration(t *testing.T) {
	h := separateHandler(t)
	now := monotime.Now()
	var tracker packetTracker
	require.EqualValues(t, 37, sendInSpace(h, now, protocol.EncryptionInitial, &tracker))
	require.EqualValues(t, 0, sendInSpace(h, now, protocol.Encryption0RTT, &tracker))
	h.ResetForRetry(now.Add(20 * time.Millisecond))
	require.ElementsMatch(t, []protocol.PacketNumber{37, 0}, tracker.Lost)
	require.Zero(t, h.bytesInFlight)
	require.EqualValues(t, 38, sendInSpace(h, now, protocol.EncryptionInitial, &tracker), "Retry must not reuse a packet number")
	require.EqualValues(t, 1, sendInSpace(h, now, protocol.Encryption0RTT, &tracker))
	require.EqualValues(t, 0, sendInSpace(h, now, protocol.EncryptionHandshake, &tracker))
	require.EqualValues(t, 2, sendInSpace(h, now, protocol.Encryption1RTT, &tracker), "0-RTT and 1-RTT share one counter")
	h.DropPackets(protocol.Encryption0RTT, now)
	require.EqualValues(t, 3*1257, h.bytesInFlight)
	h.DropPackets(protocol.EncryptionInitial, now)
	h.DropPackets(protocol.EncryptionHandshake, now)
	require.EqualValues(t, 1257, h.bytesInFlight)
	h.MigratedPath(now, 1357)
	require.Zero(t, h.bytesInFlight)
	require.EqualValues(t, 3, sendInSpace(h, now, protocol.Encryption1RTT, &tracker))
}

func TestSeparateSpacesLossAndSpuriousCongestionIdentity(t *testing.T) {
	h := separateHandler(t)
	now := monotime.Now()
	var tracker packetTracker
	sendInSpace(h, now, protocol.EncryptionInitial, &tracker)
	sendInSpace(h, now, protocol.EncryptionHandshake, &tracker)
	for range 5 {
		sendInSpace(h, now, protocol.Encryption1RTT, &tracker)
	}
	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(4)}, protocol.Encryption1RTT, now.Add(time.Millisecond))
	require.NoError(t, err)
	require.Contains(t, tracker.Lost, protocol.PacketNumber(0))
	// App wire PN 0 was transmission 2. Spurious reports must retain that ID.
	require.EqualValues(t, 2, h.lostPackets.CongestionNumber(0))
	spurious, _ := h.detectSpuriousLosses(&wire.AckFrame{AckRanges: ackRanges(0)}, now.Add(2*time.Millisecond))
	require.Equal(t, []protocol.PacketNumber{2}, spurious)
	require.EqualValues(t, 37, h.history(protocol.PacketNumberSpaceInitial).FirstPacketNumber())
	require.EqualValues(t, 0, h.history(protocol.PacketNumberSpaceHandshake).FirstPacketNumber())
}

func TestDisabledPacketNumberSkippingIncludesPTO(t *testing.T) {
	for _, separate := range []bool{false, true} {
		h := NewSentPacketHandler(37, 1257, utils.NewRTTStats(), new(utils.ConnectionStats), false, false, nil,
			protocol.PerspectiveClient, nil, utils.DefaultLogger, ClientSendConfig{
				SeparatePacketNumberSpaces: separate, DisablePacketNumberSkipping: true,
			}).(*sentPacketHandler)
		h.packetNumbers(protocol.PacketNumberSpaceAppData).packetsUntilSkip = 0
		now := monotime.Now()
		var tracker packetTracker
		first := sendInSpace(h, now, protocol.Encryption1RTT, &tracker)
		want := protocol.PacketNumber(37)
		if separate {
			want = 0
		}
		require.Equal(t, want, first, "forced random skip is disabled")
		_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(first)}, protocol.Encryption1RTT, now.Add(time.Millisecond))
		require.NoError(t, err)
		sendInSpace(h, now.Add(time.Millisecond), protocol.Encryption1RTT, &tracker)
		h.DropPackets(protocol.EncryptionHandshake, now.Add(time.Millisecond))
		err = h.OnLossDetectionTimeout(h.GetLossDetectionTimeout())
		require.NoError(t, err)
		pn, _ := h.PeekPacketNumber(protocol.PacketNumberSpaceAppData)
		require.Equal(t, first+2, pn, "PTO does not create an artificial wire gap")
		require.Equal(t, SendPTOAppData, h.ptoMode)
	}
}
