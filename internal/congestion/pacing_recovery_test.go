package congestion

import (
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func pacingSender(algorithm PacingAlgorithm, rtt time.Duration) (*cubicSender, *mockClock) {
	clock := mockClock(monotime.Now())
	stats := utils.NewRTTStats()
	stats.UpdateRTT(rtt, 0)
	s := NewConfiguredSender(&clock, stats, new(utils.ConnectionStats), 1257, SenderConfig{
		Algorithm: AlgorithmCubic, SlowStart: SlowStartClassic, InitialWindowPackets: 10,
		Pacing: &PacingConfig{Algorithm: algorithm, BurstPackets: 2, LumpyPackets: 2,
			LumpyWindowFraction: 250, LumpyMinBandwidth: 150000, Granularity: time.Millisecond,
			SlowStartGain: 2000, AvoidanceGain: 2000},
	}, nil)
	return s, &clock
}

func TestLeakyPacingBurstDebtAndIdle(t *testing.T) {
	s, clock := pacingSender(PacingLeakyBucket, 100*time.Millisecond)
	require.True(t, s.HasPacingBudget(clock.Now()))
	s.OnPacketSent(clock.Now(), 0, 0, 1257, true)
	s.OnPacketSent(clock.Now(), 1257, 1, 1257, true)
	require.False(t, s.HasPacingBudget(clock.Now()))
	require.Equal(t, clock.Now().Add(5*time.Millisecond), s.TimeUntilSend(2514))
	clock.Advance(5 * time.Millisecond)
	require.True(t, s.HasPacingBudget(clock.Now()))
	s.OnPacketSent(clock.Now(), 2514, 2, 1257, true)
	require.Zero(t, s.pacing.credit)
	clock.Advance(time.Second)
	s.OnPacketSent(clock.Now(), 0, 3, 1257, true)
	require.Equal(t, s.pacing.capacity, s.pacing.credit, "idle capacity is capped after spending, as in the source scheduler")
	// Under 1ms, sending is allowed immediately but spends signed debt.
	s.rttStats.UpdateRTT(time.Millisecond, 0)
	s.congestionWindow = 1000 * 1257
	for i := 0; i < 10; i++ {
		s.OnPacketSent(clock.Now(), 0, protocol.PacketNumber(i+4), 1257, true)
	}
	require.Negative(t, s.pacing.credit)
	require.True(t, s.HasPacingBudget(clock.Now()))
	// Lower rate must pay the debt before the next send.
	s.congestionWindow = 2 * 1257
	require.False(t, s.HasPacingBudget(clock.Now()))
	require.Greater(t, s.TimeUntilSend(1257), clock.Now())
}

func TestScheduledPacingLossAndACKOnly(t *testing.T) {
	s, clock := pacingSender(PacingScheduled, 100*time.Millisecond)
	for pn := protocol.PacketNumber(0); pn < 2; pn++ {
		s.OnPacketSent(clock.Now(), protocol.ByteCount(pn)*1257, pn, 1257, true)
	}
	require.Zero(t, s.pacing.burst)
	s.OnPacketSent(clock.Now(), 2514, 2, 1257, true)
	require.False(t, s.HasPacingBudget(clock.Now()), "low bandwidth disables lumpy burst")
	next := s.TimeUntilSend(3771)
	s.OnPacketSent(clock.Now(), 3771, 3, 40, false)
	require.Equal(t, next, s.TimeUntilSend(3771), "pure ACK must not consume scheduled pacing credit")
	clock.Advance(4 * time.Millisecond)
	require.True(t, s.HasPacingBudget(clock.Now()), "1ms alarm tolerance")
	s.OnCongestionEvent(0, 1257, 3771)
	require.Zero(t, s.pacing.burst, "a loss cancels idle burst credit")
}

func TestScheduledPacingApplicationPauseDoesNotAccumulateSendDebt(t *testing.T) {
	s, clock := pacingSender(PacingScheduled, 100*time.Millisecond)
	for pn := protocol.PacketNumber(0); pn < 3; pn++ {
		s.OnPacketSent(clock.Now(), protocol.ByteCount(pn)*1257, pn, 1257, true)
	}
	require.True(t, s.pacing.limited)
	clock.Advance(time.Second)
	s.OnApplicationLimited()
	s.OnPacketSent(clock.Now(), 3*1257, 3, 1257, true)
	require.Greater(t, s.pacing.next, clock.Now(), "application idle time is not pacing credit")
}

func TestPRRAllowanceAndRecoveryBoundary(t *testing.T) {
	s := configuredSender(SenderConfig{Algorithm: AlgorithmCubicBytes, PRR: true, SegmentSize: 1460})
	now := monotime.Now()
	for pn := protocol.PacketNumber(0); pn < 32; pn++ {
		s.OnPacketSent(now, protocol.ByteCount(pn)*1460, pn, 1460, true)
	}
	s.OnPacketAcked(0, 1460, 32*1460, now)
	s.OnCongestionEvent(1, 1460, 31*1460)
	require.True(t, s.InRecovery())
	require.True(t, s.CanSend(30*1460), "limited transmit grants the first recovery send")
	s.OnPacketSent(now, 30*1460, 32, 1460, true)
	require.False(t, s.CanSend(31*1460))
	s.OnPacketAcked(2, 4*1460, 31*1460, now)
	require.True(t, s.CanSend(27*1460), "PRR releases send credit after delivery")
	w := s.congestionWindow
	s.OnPacketAcked(3, 1460, 27*1460, now)
	require.Equal(t, w, s.congestionWindow, "ACKs from before recovery cannot grow cwnd")
	s.OnPacketAcked(32, 1460, 26*1460, now)
	require.False(t, s.InRecovery())
	s.OnRetransmissionTimeout(true)
	require.Equal(t, prr{}, s.prr)
}

func TestPersistentCongestionClearsGrowthAndUndo(t *testing.T) {
	s := configuredSender(SenderConfig{Algorithm: AlgorithmCubic, SlowStart: SlowStartClassic, RecoveryBurstPackets: 1})
	now := monotime.Now()
	s.OnPacketSent(now, 0, 0, 1257, true)
	s.OnCongestionEvent(0, 1257, 1257)
	require.True(t, s.CanSend(s.congestionWindow+1257))
	s.OnPacketSent(now, 1257, 1, 1257, true)
	require.False(t, s.CanSend(s.congestionWindow+1257))
	s.OnPersistentCongestion()
	require.EqualValues(t, 2*1257, s.congestionWindow)
	require.True(t, s.InSlowStart())
	require.False(t, s.undoState.IsActive())
	s.OnSpuriousLoss(0)
	require.EqualValues(t, 2*1257, s.congestionWindow, "obsolete undo must not undo persistent congestion")
	s.OnPacketAcked(0, 1257, 2*1257, now)
	require.EqualValues(t, 2*1257, s.congestionWindow, "pre-collapse ACKs cannot regrow the reset window")
	s.OnPacketSent(now, 0, 2, 1257, true)
	s.OnPacketAcked(2, 1257, 1257, now)
	require.Greater(t, s.congestionWindow, protocol.ByteCount(2*1257))
}

func TestRFCRecoveryRejectsLatePreCutbackACKAfterRecovery(t *testing.T) {
	s := configuredSender(SenderConfig{Algorithm: AlgorithmCubic, SlowStart: SlowStartClassic})
	now := monotime.Now()
	s.OnPacketSent(now, s.congestionWindow, 10, 1257, true)
	s.OnPacketAcked(0, 1257, s.congestionWindow, now)
	s.OnCongestionEvent(1, 1257, s.congestionWindow)
	s.OnPacketSent(now, s.congestionWindow, 11, 1257, true)
	s.OnPacketAcked(11, 1257, s.congestionWindow, now)
	require.False(t, s.InRecovery())
	before := *s.rfcCubic
	s.BeginAck()
	s.OnPacketAcked(1, 1257, s.congestionWindow, now.Add(time.Second))
	s.EndAck(now.Add(time.Second))
	require.Equal(t, before, *s.rfcCubic, "an old packet must not contribute fresh avoidance credit")
}
