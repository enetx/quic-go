package ackhandler

import (
	"fmt"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestClientPacketPolicySeparateHistories(t *testing.T) {
	for _, separate := range []bool{false, true} {
		t.Run(fmt.Sprint(separate), func(t *testing.T) {
			h := policyTestHandler(protocol.PerspectiveClient)
			if separate {
				h.separateSpaces = newSeparatePacketNumberSpaces(0)
			}
			// Include Initial, 0-RTT, 1-RTT, a path probe and a removed ACK-only
			// slot. Only the current space's retained regular packets may count.
			initial := h.history(protocol.PacketNumberSpaceInitial)
			initial.SentPacket(0, &packet{EncryptionLevel: protocol.EncryptionInitial})
			app := h.history(protocol.PacketNumberSpaceAppData)
			app.SentPacket(1, &packet{EncryptionLevel: protocol.Encryption0RTT})
			app.SentPacket(2, &packet{EncryptionLevel: protocol.Encryption1RTT})
			app.SentPacket(3, &packet{EncryptionLevel: protocol.Encryption1RTT})
			app.SentPathProbePacket(4, &packet{EncryptionLevel: protocol.Encryption1RTT})
			require.NoError(t, app.Remove(2))
			var snapshot PacketNumberLengthInfo
			SetPacketNumberLengthPolicy(h, func(info PacketNumberLengthInfo) uint8 { snapshot = info; return 1 })
			h.packetNumberLength(5, -1, protocol.PacketNumberSpaceAppData)
			require.EqualValues(t, 1, snapshot.LeastUnacknowledged)
			h.packetNumberLength(5, -1, protocol.PacketNumberSpaceInitial)
			require.Zero(t, snapshot.LeastUnacknowledged)
			require.True(t, AckProbeNeeded(h, monotime.Now(), func(info AckProbeInfo) bool {
				require.EqualValues(t, 2, info.OutstandingPackets)
				return true
			}))
		})
	}
}

func policyTestHandler(pers protocol.Perspective) *sentPacketHandler {
	return NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, false, false, nil, pers, nil, utils.DefaultLogger).(*sentPacketHandler)
}

func TestClientPacketNumberLengthSafety(t *testing.T) {
	h := policyTestHandler(protocol.PerspectiveClient)
	SetPacketNumberLengthPolicy(h, func(PacketNumberLengthInfo) uint8 { return 1 })
	for _, tc := range []struct {
		pn, ack protocol.PacketNumber
		want    protocol.PacketNumberLen
	}{
		{0, -1, 1}, {254, -1, 1}, {255, -1, 2}, {127, 0, 1}, {128, 0, 2},
		{32767, 0, 2}, {32768, 0, 3}, {8388607, 0, 3}, {8388608, 0, 4}, {1 << 30, -1, 4},
	} {
		require.Equal(t, tc.want, h.packetNumberLength(tc.pn, tc.ack, protocol.PacketNumberSpaceAppData))
	}
	for _, invalid := range []uint8{0, 5, 255} {
		SetPacketNumberLengthPolicy(h, func(PacketNumberLengthInfo) uint8 { return invalid })
		require.Equal(t, protocol.PacketNumberLen2, h.packetNumberLength(0, -1, protocol.PacketNumberSpaceInitial))
	}
	server := policyTestHandler(protocol.PerspectiveServer)
	SetPacketNumberLengthPolicy(server, func(PacketNumberLengthInfo) uint8 { t.Fatal("client policy called for server"); return 1 })
	_, length := server.PeekPacketNumber(protocol.PacketNumberSpaceInitial)
	require.Equal(t, protocol.PacketNumberLen2, length)
}

func TestClientPacketPolicyRecoverySnapshots(t *testing.T) {
	h := policyTestHandler(protocol.PerspectiveClient)
	// The snapshot includes tracked ACK-only packets but ignores removed slots
	// and packets from other packet-number spaces.
	h.hist.SentPacket(0, &packet{EncryptionLevel: protocol.EncryptionInitial})
	h.hist.SentPacket(1, &packet{EncryptionLevel: protocol.Encryption0RTT})
	h.hist.SentPacket(2, &packet{EncryptionLevel: protocol.Encryption1RTT})
	h.hist.SentPacket(3, &packet{EncryptionLevel: protocol.Encryption1RTT})
	require.NoError(t, h.hist.Remove(2))
	var snapshot PacketNumberLengthInfo
	SetPacketNumberLengthPolicy(h, func(info PacketNumberLengthInfo) uint8 { snapshot = info; return 1 })
	h.packetNumberLength(4, -1, protocol.PacketNumberSpaceAppData)
	require.EqualValues(t, 1, snapshot.LeastUnacknowledged)
	require.EqualValues(t, h.congestion.GetCongestionWindow()/1200, snapshot.MaxPacketsInFlight)
	h.SetMaxDatagramSize(1400)
	h.packetNumberLength(4, -1, protocol.PacketNumberSpaceAppData)
	require.EqualValues(t, h.congestion.GetCongestionWindow()/1400, snapshot.MaxPacketsInFlight)
	now := monotime.Now()
	check := func(info AckProbeInfo) bool {
		require.EqualValues(t, 2, info.OutstandingPackets)
		require.False(t, info.HasLastAckEliciting)
		require.Zero(t, info.SinceLastAckEliciting)
		require.Equal(t, h.rttStats.PTO(false), info.PTO)
		return true
	}
	require.True(t, AckProbeNeeded(h, now, check))
	h.appDataPackets.lastAckElicitingPacketTime = now.Add(-100 * time.Millisecond)
	h.handshakeConfirmed = true
	require.False(t, AckProbeNeeded(h, now, func(info AckProbeInfo) bool {
		require.True(t, info.HasLastAckEliciting)
		require.Equal(t, 100*time.Millisecond, info.SinceLastAckEliciting)
		require.Equal(t, h.rttStats.PTO(true), info.PTO)
		return false
	}))
	require.False(t, AckProbeNeeded(h, now, nil))
	require.False(t, AckProbeNeeded(policyTestHandler(protocol.PerspectiveServer), now, func(AckProbeInfo) bool { t.Fatal("server policy"); return true }))
}

func TestClientPacketNumberCoalescedSizeSnapshot(t *testing.T) {
	h := policyTestHandler(protocol.PerspectiveClient)
	var snapshot PacketNumberLengthInfo
	SetPacketNumberLengthPolicy(h, func(info PacketNumberLengthInfo) uint8 {
		snapshot = info
		if info.CoalescedMaxPacketsInFlight > info.MaxPacketsInFlight {
			return 3
		}
		return 1
	})
	_, initialLength := h.PeekPacketNumber(protocol.PacketNumberSpaceInitial)
	require.Equal(t, protocol.PacketNumberLen1, initialLength)
	require.Zero(t, snapshot.CoalescedMaxPacketsInFlight)
	SetCoalescedPacketSize(h, protocol.PacketNumberSpaceInitial, 262)
	_, limitedLength := h.PeekPacketNumber(protocol.PacketNumberSpaceInitial)
	require.Equal(t, protocol.PacketNumberLen3, limitedLength, "the application policy receives the live temporary estimate")
	require.EqualValues(t, h.congestion.GetCongestionWindow()/262, snapshot.CoalescedMaxPacketsInFlight)
	require.EqualValues(t, h.congestion.GetCongestionWindow()/1200, snapshot.MaxPacketsInFlight)
	require.EqualValues(t, 1200, h.maxDatagramSize, "temporary budget must not change path MTU or congestion")
	_, handshakeLength := h.PeekPacketNumber(protocol.PacketNumberSpaceHandshake)
	require.Equal(t, protocol.PacketNumberLen1, handshakeLength)
	require.Zero(t, snapshot.CoalescedMaxPacketsInFlight, "another number space discards the temporary limit")
	h.PeekPacketNumber(protocol.PacketNumberSpaceInitial)
	require.Zero(t, snapshot.CoalescedMaxPacketsInFlight, "returning to the previous space does not resurrect its limit")
	for _, size := range []protocol.ByteCount{0, -1} {
		SetCoalescedPacketSize(h, protocol.PacketNumberSpaceInitial, size)
		h.PeekPacketNumber(protocol.PacketNumberSpaceInitial)
		require.Zero(t, snapshot.CoalescedMaxPacketsInFlight)
	}
	SetCoalescedPacketSize(h, protocol.PacketNumberSpaceInitial, 262)
	h.SetMaxDatagramSize(1400)
	h.PeekPacketNumber(protocol.PacketNumberSpaceInitial)
	require.Zero(t, snapshot.CoalescedMaxPacketsInFlight, "a changed path MTU discards its old temporary budget")
	require.EqualValues(t, h.congestion.GetCongestionWindow()/1400, snapshot.MaxPacketsInFlight)
	SetCoalescedPacketSize(h, protocol.PacketNumberSpaceInitial, 262)
	h.ResetForRetry(monotime.Now())
	h.PeekPacketNumber(protocol.PacketNumberSpaceInitial)
	require.Zero(t, snapshot.CoalescedMaxPacketsInFlight, "Retry starts a new packet-size context")
	server := policyTestHandler(protocol.PerspectiveServer)
	SetCoalescedPacketSize(server, protocol.PacketNumberSpaceInitial, 262)
	require.Zero(t, server.coalescedPacketSize)
	_, nativeLength := server.PeekPacketNumber(protocol.PacketNumberSpaceInitial)
	require.Equal(t, protocol.PacketNumberLen2, nativeLength)
}
