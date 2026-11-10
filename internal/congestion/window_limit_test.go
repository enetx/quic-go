package congestion

import (
	"math"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestConfiguredWindowCeiling(t *testing.T) {
	for _, algorithm := range []Algorithm{AlgorithmReno, AlgorithmCubic, AlgorithmCubicBytes} {
		for _, limit := range []int64{0, 2000, -1} {
			s := configuredSender(SenderConfig{Algorithm: algorithm, SlowStart: SlowStartClassic, MaxWindowPackets: limit, SegmentSize: 1460})
			want := protocol.ByteCount(10000 * 1460)
			if limit > 0 {
				want = protocol.ByteCount(limit) * 1460
			}
			if limit < 0 {
				want = protocol.MaxByteCount
			}
			require.Equal(t, want, s.maxCongestionWindow())
			if limit != 0 {
				require.Equal(t, want, s.slowStartThreshold)
			}
			s.SetMaxDatagramSize(1350)
			require.Equal(t, want, s.maxCongestionWindow(), "accounting segment is independent of path MTU")
			if limit >= 0 {
				s.congestionWindow = want - 1
				s.firstAppLimited = 2
				s.OnPacketAcked(1, 1460, want, monotime.Now())
				require.Equal(t, want, s.congestionWindow, "growth may not overshoot a nonaligned ceiling")
				if limit > 0 {
					require.False(t, s.InSlowStart(), "a configured ceiling also ends initial slow start")
				}
			} else {
				s.congestionWindow = 20000 * 1460
				s.firstAppLimited = 2
				s.OnPacketAcked(1, 1460, s.congestionWindow, monotime.Now())
				require.Greater(t, s.congestionWindow, protocol.ByteCount(20000*1460))
			}
			s.OnConnectionMigration()
			require.Equal(t, s.initialCongestionWindow, s.congestionWindow)
			require.Equal(t, want, s.slowStartThreshold)
		}
	}
}

func TestUnboundedWindowArithmetic(t *testing.T) {
	var c rfcCubic
	now := monotime.Now()
	w := protocol.ByteCount(1 << 48)
	for i := range 20 {
		next := c.afterAck(w, 1257, 1257, time.Millisecond, now.Add(time.Duration(i)*time.Millisecond))
		require.GreaterOrEqual(t, next, w)
		w = next
	}
	require.EqualValues(t, 1000*8, BandwidthFromDelta(1000, time.Second))
	require.EqualValues(t, uint64(math.MaxUint64/8*8), BandwidthFromDelta(protocol.MaxByteCount, time.Nanosecond))
	require.Zero(t, BandwidthFromDelta(1, 0))
}
