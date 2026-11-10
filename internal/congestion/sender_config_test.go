package congestion

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestRFC9438OriginalNeqoVectors(t *testing.T) {
	var vectors []struct {
		Scenario string
		MSS      protocol.ByteCount
		RTTMS    int `json:"rtt_ms"`
		Steps    [][4]int64
	}
	data, err := os.ReadFile("testdata/rfc9438_vectors.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &vectors))
	for _, v := range vectors {
		t.Run(fmt.Sprintf("%s/%d", v.Scenario, v.MSS), func(t *testing.T) {
			var c rfcCubic
			cwnd := c.afterLoss(100*v.MSS, v.MSS, v.Scenario == "ecn")
			now := monotime.Now()
			for i, row := range v.Steps {
				if v.Scenario == "fast-convergence" && i == 10 {
					cwnd = c.afterLoss(cwnd, v.MSS, false)
				}
				if v.Scenario == "idle" && i == 20 {
					c.epoch = 0
				}
				if v.Scenario == "undo" && i == 10 {
					saved := c
					c.afterLoss(cwnd, v.MSS, false)
					c = saved
					cwnd = 70 * v.MSS
					c.acked = 0
				}
				cwnd = c.afterAck(cwnd, protocol.ByteCount(row[1]), v.MSS, time.Duration(v.RTTMS)*time.Millisecond, now.Add(time.Duration(row[0])*time.Millisecond))
				require.EqualValues(t, row[2], cwnd, "step %d", i)
				require.EqualValues(t, row[3], c.acked, "step %d", i)
			}
		})
	}
}

func configuredSender(config SenderConfig) *cubicSender {
	return NewConfiguredSender(DefaultClock{}, utils.NewRTTStats(), new(utils.ConnectionStats), 1257, config, nil)
}

func TestConfiguredCongestionSlowStart(t *testing.T) {
	for _, algorithm := range []Algorithm{AlgorithmNative, AlgorithmReno, AlgorithmCubic, AlgorithmCubicBytes} {
		for _, slow := range []SlowStart{SlowStartNative, SlowStartHybrid, SlowStartClassic} {
			s := configuredSender(SenderConfig{Algorithm: algorithm, SlowStart: slow, InitialWindowPackets: 10})
			before := s.GetCongestionWindow()
			now := monotime.Now()
			for pn := protocol.PacketNumber(1); pn <= 10; pn++ {
				s.OnPacketSent(now, protocol.ByteCount(pn-1)*1257, pn, 1257, true)
			}
			s.BeginAck()
			s.OnPacketAcked(1, 100, before, now)
			s.OnPacketAcked(2, 900, before, now)
			s.EndAck(now)
			growth := protocol.ByteCount(2 * 1257)
			if slow == SlowStartClassic {
				growth = 1000
			}
			require.Equal(t, before+growth, s.GetCongestionWindow())
			require.EqualValues(t, s.GetCongestionWindow(), s.connStats.CongestionWindow.Load())
			// Classic ignores delay-based HyStart exit; a real loss still exits.
			s.hybridSlowStart.hystartFound = true
			s.congestionWindow = 20 * 1257
			s.MaybeExitSlowStart()
			require.Equal(t, slow == SlowStartClassic, s.InSlowStart())
			s.OnCongestionEvent(1, 1257, before)
			require.False(t, s.InSlowStart())
		}
	}
}

func TestRFC9438AckBatchAndSentWindowUtilization(t *testing.T) {
	s := configuredSender(SenderConfig{Algorithm: AlgorithmCubic, SlowStart: SlowStartClassic, InitialWindowPackets: 10})
	now := monotime.Now()
	before := s.congestionWindow
	s.OnPacketSent(now, 0, 1, 100, true)
	s.OnPacketAcked(1, 100, before, now)
	require.Equal(t, before, s.congestionWindow, "an application-limited send must not grow")
	for pn := protocol.PacketNumber(2); pn <= 11; pn++ {
		s.OnPacketSent(now, protocol.ByteCount(pn-2)*1257, pn, 1257, true)
	}
	s.BeginAck()
	for pn := protocol.PacketNumber(2); pn <= 11; pn++ {
		s.OnPacketAcked(pn, 1257, 0, now)
	}
	require.Equal(t, before, s.congestionWindow, "growth is deferred until all packets in the ACK are counted")
	s.EndAck(now)
	require.Equal(t, 2*before, s.congestionWindow, "delayed ACK of a full send is not application-limited")
	// After the loss, all pre-cutback ACKs are excluded from growth.
	s.OnCongestionEvent(2, 1257, 0)
	reduced := s.congestionWindow
	s.BeginAck()
	s.OnPacketAcked(11, 1257, 0, now)
	s.EndAck(now)
	require.Equal(t, reduced, s.congestionWindow)
}

func TestRFC9438CutbackUndoAndECN(t *testing.T) {
	s := configuredSender(SenderConfig{Algorithm: AlgorithmCubic, SlowStart: SlowStartClassic})
	now := monotime.Now()
	s.OnPacketSent(now, s.congestionWindow, 10, 1257, true)
	s.largestAckedPacketNumber = 0
	before := s.congestionWindow
	s.rfcCubic.wMax = 123456
	s.rfcCubic.acked = 987
	curve := *s.rfcCubic
	s.OnCongestionEvent(1, 1257, before)
	s.OnCongestionEvent(2, 1257, before)
	require.Equal(t, before*70/100, s.congestionWindow)
	s.OnSpuriousLoss(1)
	require.Less(t, s.congestionWindow, before, "another reported loss is outstanding")
	s.OnSpuriousLoss(2)
	require.Equal(t, before, s.congestionWindow)
	require.Equal(t, curve, *s.rfcCubic, "undo restores the curve and fractional credit")
	s.OnCongestionEvent(3, 0, before)
	require.Equal(t, before*85/100, s.congestionWindow, "ECN uses a distinct reduction")
	s.OnCongestionEvent(4, 1257, before)
	s.OnSpuriousLoss(4)
	require.Equal(t, before*85/100, s.congestionWindow, "undoing a loss must not undo an ECN event")
	s.OnRetransmissionTimeout(true)
	require.Equal(t, 2*s.segmentSize(), s.congestionWindow)
	require.Equal(t, rfcCubic{}, *s.rfcCubic)
}

func TestCongestionSegmentSizeAndMigration(t *testing.T) {
	s := configuredSender(SenderConfig{Algorithm: AlgorithmCubicBytes, SegmentSize: 1460, Connections: 2, InitialWindowPackets: 32})
	require.EqualValues(t, 46720, s.congestionWindow)
	require.EqualValues(t, 1257, s.maxDatagramSize)
	require.Equal(t, float32(.85), s.cubic.beta())
	s.SetMaxDatagramSize(1357)
	require.EqualValues(t, 1460, s.segmentSize())
	require.EqualValues(t, 1460, s.cubic.segmentSize)
	s.OnCongestionEvent(1, 1257, s.congestionWindow)
	s.OnConnectionMigration()
	require.EqualValues(t, 46720, s.congestionWindow)
	require.EqualValues(t, 1460, s.cubic.segmentSize)
	require.Equal(t, 2, s.cubic.numConnections)
	dynamic := configuredSender(SenderConfig{Algorithm: AlgorithmCubicBytes})
	dynamic.SetMaxDatagramSize(1357)
	require.EqualValues(t, 1357, dynamic.cubic.segmentSize)
}

func TestCubicBytesOriginalQUICHEVectors(t *testing.T) {
	var vectors [][6]int64
	data, err := os.ReadFile("testdata/cubic_bytes_vectors.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &vectors))
	var c *Cubic
	var cwnd protocol.ByteCount
	now := monotime.Now()
	for _, row := range vectors {
		if row[2] == 0 {
			c = NewCubic(DefaultClock{})
			c.segmentSize = 1460
			c.SetNumConnections(int(row[0]))
			cwnd = c.CongestionWindowAfterPacketLoss(100 * 1460)
		}
		if row[1] == 2 && row[2] == 20 {
			c.OnApplicationLimited()
		}
		if row[1] == 2 && row[2] == 40 {
			cwnd = c.CongestionWindowAfterPacketLoss(cwnd)
		}
		cwnd = c.CongestionWindowAfterAck(protocol.ByteCount(row[4]), cwnd, 100*time.Millisecond, now.Add(time.Duration(row[3])*time.Millisecond))
		require.EqualValues(t, row[5], cwnd, "connections=%d scenario=%d step=%d state=%+v alpha=%x", row[0], row[1], row[2], c, c.alpha())
	}
}

func TestConfiguredNativePreservesDefaultSender(t *testing.T) {
	for _, mtu := range []protocol.ByteCount{1200, 1257, 1280, 1460} {
		rtt := utils.NewRTTStats()
		var clock mockClock = 1
		native := NewCubicSender(&clock, rtt, new(utils.ConnectionStats), mtu, true, nil)
		configured := NewConfiguredSender(&clock, rtt, new(utils.ConnectionStats), mtu, SenderConfig{}, nil)
		require.Equal(t, native, configured)
	}
}
