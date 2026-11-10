package ackhandler

import (
	"math"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestLegacyAckFrequencySequenceAndPendingTimer(t *testing.T) {
	h := NewReceivedPacketHandler(utils.DefaultLogger)
	h.SetAckPolicy(&AckPolicy{PacketThreshold: 2, ECN: AckECNCountOnly}, nil)
	h.SetLegacyAckFrequency(time.Millisecond)
	tracker := &h.appDataPackets
	now := monotime.Now()
	require.NoError(t, tracker.ReceivedPacket(0, protocol.ECNNon, now, true))
	oldAlarm := tracker.ackAlarm
	f := &wire.LegacyAckFrequencyFrame{SequenceNumber: 3, AckElicitingThreshold: 4, RequestMaxAckDelay: 5 * time.Millisecond, IgnoreOrder: true}
	require.NoError(t, h.HandleLegacyAckFrequency(f))
	require.Equal(t, oldAlarm, tracker.ackAlarm)
	for pn := protocol.PacketNumber(1); pn <= 3; pn++ {
		require.NoError(t, tracker.ReceivedPacket(pn, protocol.ECNNon, now, true))
		require.Equal(t, pn == 3, tracker.ackQueued)
	}
	require.NotNil(t, tracker.GetAckFrame(now, true))
	copy := *f
	copy.SequenceNumber, copy.AckElicitingThreshold = 2, 1
	require.NoError(t, h.HandleLegacyAckFrequency(&copy))
	require.EqualValues(t, 4, tracker.legacyAckFrequency.threshold, "stale updates are ignored")
	copy.SequenceNumber, copy.AckElicitingThreshold = 3, 2
	require.NoError(t, h.HandleLegacyAckFrequency(&copy))
	require.EqualValues(t, 2, tracker.legacyAckFrequency.threshold, "Neqo accepts equal sequence updates")
	require.NoError(t, tracker.ReceivedPacket(4, protocol.ECNCE, now, true))
	require.False(t, tracker.ackQueued, "ECN is counted without changing the negotiated threshold")
	require.Nil(t, tracker.GetAckFrame(now.Add(5*time.Millisecond-time.Nanosecond), true))
	require.NotNil(t, tracker.GetAckFrame(now.Add(5*time.Millisecond), true))
	require.Error(t, tracker.ReceivedPacket(4, protocol.ECNNon, now, true))
	require.Zero(t, tracker.ackElicitingPacketsReceivedSinceLastAck)
	copy.RequestMaxAckDelay = time.Microsecond
	require.Error(t, h.HandleLegacyAckFrequency(&copy), "invalid delay is rejected even for an old sequence")
	copy.RequestMaxAckDelay, copy.AckElicitingThreshold = time.Millisecond, 0
	require.Error(t, h.HandleLegacyAckFrequency(&copy))
	// Neither a peer request nor local configuration changes Initial ACK policy.
	require.NoError(t, h.ReceivedPacket(0, protocol.ECNNon, protocol.EncryptionInitial, now, true))
	require.NotNil(t, h.GetAckFrame(protocol.EncryptionInitial, now, true))
}

func TestLegacyAckFrequencyReorderingAndTimerOverflow(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		h := NewReceivedPacketHandler(utils.DefaultLogger)
		h.SetLegacyAckFrequency(time.Millisecond)
		f := &wire.LegacyAckFrequencyFrame{AckElicitingThreshold: 10, RequestMaxAckDelay: 3 * time.Millisecond, IgnoreOrder: ignore}
		require.NoError(t, h.HandleLegacyAckFrequency(f))
		now := monotime.Now()
		require.NoError(t, h.appDataPackets.ReceivedPacket(0, protocol.ECNNon, now, false))
		require.Zero(t, h.appDataPackets.ackAlarm)
		require.NoError(t, h.appDataPackets.ReceivedPacket(2, protocol.ECNNon, now, true))
		require.Equal(t, !ignore, h.appDataPackets.ackQueued)
		if ignore {
			alarm := h.appDataPackets.ackAlarm
			require.NoError(t, h.appDataPackets.ReceivedPacket(1, protocol.ECNNon, now.Add(time.Millisecond), true))
			require.Equal(t, alarm, h.appDataPackets.ackAlarm)
		}
	}
	h := NewReceivedPacketHandler(utils.DefaultLogger)
	f := &wire.LegacyAckFrequencyFrame{AckElicitingThreshold: 10, RequestMaxAckDelay: time.Duration(math.MaxInt64), IgnoreOrder: true}
	require.Error(t, h.HandleLegacyAckFrequency(f))
	h.SetLegacyAckFrequency(time.Millisecond)
	require.NoError(t, h.HandleLegacyAckFrequency(f))
	require.NoError(t, h.appDataPackets.ReceivedPacket(0, protocol.ECNNon, monotime.Now(), true))
	require.Equal(t, monotime.Time(math.MaxInt64), h.GetAlarmTimeout())
}
