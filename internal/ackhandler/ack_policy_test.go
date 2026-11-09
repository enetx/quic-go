package ackhandler

import (
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func policyTracker(p *AckPolicy, rtt time.Duration) *appDataReceivedPacketTracker {
	h := NewReceivedPacketHandler(utils.DefaultLogger)
	r := utils.NewRTTStats()
	if rtt > 0 {
		r.UpdateRTT(rtt, 0)
	}
	h.SetAckPolicy(p, r)
	return &h.appDataPackets
}

func TestAckPolicyPacketNumberSpanAndTimer(t *testing.T) {
	p := &AckPolicy{PacketThreshold: 2, DecimationThreshold: 10, DecimationAfter: 100, RTTDivisor: 4, MinDelay: time.Millisecond}
	h := policyTracker(p, 40*time.Millisecond)
	start := monotime.Now()
	// Start at a nonzero number, with non-eliciting packets before the transition.
	for pn := protocol.PacketNumber(500); pn < 600; pn++ {
		eliciting := pn == 500 || pn == 599
		require.NoError(t, h.ReceivedPacket(pn, protocol.ECNNon, start, eliciting))
		if pn == 500 {
			require.False(t, h.ackQueued)
			require.Equal(t, start.Add(25*time.Millisecond), h.ackAlarm)
		}
	}
	require.True(t, h.ackQueued, "the initial threshold is still two at span 99")
	require.NotNil(t, h.GetAckFrame(start, true))
	require.NoError(t, h.ReceivedPacket(600, protocol.ECNNon, start, true))
	require.False(t, h.ackQueued)
	require.Equal(t, start.Add(10*time.Millisecond), h.ackAlarm)
	for pn := protocol.PacketNumber(601); pn < 609; pn++ {
		require.NoError(t, h.ReceivedPacket(pn, protocol.ECNNon, start.Add(time.Millisecond), true))
		require.False(t, h.ackQueued)
	}
	require.Equal(t, start.Add(10*time.Millisecond), h.ackAlarm, "later packets must not slide the pending timer")
	require.NoError(t, h.ReceivedPacket(609, protocol.ECNNon, start.Add(time.Millisecond), true))
	require.True(t, h.ackQueued)
	ack := h.GetAckFrame(start.Add(time.Millisecond), true)
	require.NotNil(t, ack)
	require.Zero(t, h.ackElicitingPacketsReceivedSinceLastAck)
	// Duplicate packets are rejected before policy state is touched.
	require.Error(t, h.ReceivedPacket(609, protocol.ECNNon, start, true))
	require.Zero(t, h.ackElicitingPacketsReceivedSinceLastAck)
}

func TestAckPolicyRTTBoundsAndDeadline(t *testing.T) {
	for _, tc := range []struct{ rtt, want time.Duration }{{0, time.Millisecond}, {2 * time.Millisecond, time.Millisecond}, {40 * time.Millisecond, 10 * time.Millisecond}, {time.Second, 25 * time.Millisecond}} {
		t.Run(tc.rtt.String(), func(t *testing.T) {
			h := policyTracker(&AckPolicy{DecimationThreshold: 10, RTTDivisor: 4, MinDelay: time.Millisecond}, tc.rtt)
			now := monotime.Now()
			require.NoError(t, h.ReceivedPacket(0, protocol.ECNNon, now, true))
			require.Equal(t, now.Add(tc.want), h.ackAlarm)
			require.Nil(t, h.GetAckFrame(now.Add(tc.want-time.Nanosecond), true))
			require.NotNil(t, h.GetAckFrame(now.Add(tc.want), true))
		})
	}
}

func TestAckPolicyGapWindowAndPreviouslyMissing(t *testing.T) {
	h := policyTracker(&AckPolicy{PacketThreshold: 10, Reordering: AckReorderingWindow, MissingPacketAckLimit: 4}, 0)
	now := monotime.Now()
	require.NoError(t, h.ReceivedPacket(0, protocol.ECNNon, now, true))
	require.NotNil(t, h.GetAckFrame(now, false))
	for pn := protocol.PacketNumber(2); pn <= 6; pn++ {
		require.NoError(t, h.ReceivedPacket(pn, protocol.ECNNon, now, true))
		require.Equal(t, pn <= 5, h.ackQueued, "packet %d following a gap", pn)
		if pn <= 5 {
			require.NotNil(t, h.GetAckFrame(now, true))
		}
	}
	// A non-eliciting packet filling an already reported gap still prompts an
	// ACK in window mode. Its packet number is included in the resulting range.
	require.NoError(t, h.ReceivedPacket(1, protocol.ECNNon, now, false))
	require.True(t, h.ackQueued)
	ack := h.GetAckFrame(now, true)
	require.NotNil(t, ack)
	require.True(t, ack.AcksPacket(1))
}

func TestAckPolicyImmediateReorderingAndFixedDelay(t *testing.T) {
	h := policyTracker(&AckPolicy{PacketThreshold: 2, Reordering: AckReorderingImmediate, ECN: AckECNCountOnly}, 0)
	h.ackDelayLimit = 20 * time.Millisecond
	now := monotime.Now()
	require.NoError(t, h.ReceivedPacket(0, protocol.ECNCE, now, true))
	require.False(t, h.ackQueued, "count-only ECN does not itself queue an ACK")
	require.Equal(t, now.Add(20*time.Millisecond), h.ackAlarm)
	require.NoError(t, h.ReceivedPacket(1, protocol.ECNNon, now.Add(time.Millisecond), false))
	require.Equal(t, now.Add(20*time.Millisecond), h.ackAlarm)
	require.NoError(t, h.ReceivedPacket(2, protocol.ECNNon, now.Add(time.Millisecond), true))
	require.True(t, h.ackQueued)
	require.NotNil(t, h.GetAckFrame(now.Add(time.Millisecond), true))
	require.NoError(t, h.ReceivedPacket(4, protocol.ECNNon, now, true))
	require.True(t, h.ackQueued)
	require.NotNil(t, h.GetAckFrame(now, true))
	require.NoError(t, h.ReceivedPacket(3, protocol.ECNNon, now, true))
	require.True(t, h.ackQueued)
}

func TestAckPolicyECNTransitions(t *testing.T) {
	h := policyTracker(&AckPolicy{PacketThreshold: 10, ECN: AckECNTransitions}, 0)
	now := monotime.Now()
	for i, ecn := range []protocol.ECN{protocol.ECNCE, protocol.ECNCE, protocol.ECT0, protocol.ECNCE} {
		require.NoError(t, h.ReceivedPacket(protocol.PacketNumber(i), ecn, now, false))
		require.Equal(t, i == 0 || i == 3, h.ackQueued)
		if h.ackQueued {
			require.NotNil(t, h.GetAckFrame(now, true))
		}
	}
}

func TestAckPolicySnapshotsAndValidation(t *testing.T) {
	p := &AckPolicy{PacketThreshold: 10}
	h := NewReceivedPacketHandler(utils.DefaultLogger)
	h.SetAckPolicy(p, utils.NewRTTStats())
	p.PacketThreshold = 1
	require.EqualValues(t, 10, h.appDataPackets.ackPolicy.PacketThreshold)
	now := monotime.Now()
	for _, level := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake} {
		require.NoError(t, h.ReceivedPacket(0, protocol.ECNNon, level, now, true))
		require.NotNil(t, h.GetAckFrame(level, now, true), "handshake ACKs stay immediate")
	}
	for _, bad := range []*AckPolicy{{PacketThreshold: 1 << 62}, {DecimationAfter: 1 << 62}, {MinDelay: -time.Nanosecond}, {MinDelay: 26 * time.Millisecond}, {Reordering: 99}, {ECN: 99}, {Reordering: AckReorderingWindow}} {
		require.Error(t, bad.Validate(25*time.Millisecond))
	}
	require.NoError(t, (*AckPolicy)(nil).Validate(0))
	require.NoError(t, (&AckPolicy{}).Validate(25*time.Millisecond))
}
