package ackhandler

import (
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/congestion"
	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestPersistentLossRequiresContiguousSampledRange(t *testing.T) {
	start := monotime.Now()
	for _, gap := range []bool{false, true} {
		r := persistentLossRange{cutoff: start, period: 300 * time.Millisecond}
		require.False(t, r.lost(0, start.Add(-time.Second), true))
		require.False(t, r.lost(1, start, true))
		next := protocol.PacketNumber(2)
		if gap {
			next++
		}
		require.Equal(t, !gap, r.lost(next, start.Add(301*time.Millisecond), true))
	}
	r := persistentLossRange{cutoff: start, period: 300 * time.Millisecond}
	require.False(t, r.lost(0, start, false))
	require.False(t, r.lost(1, start.Add(time.Second), true), "non-eliciting packet cannot start the range")
	require.False(t, r.lost(2, start.Add(1300*time.Millisecond), true), "exact threshold does not exceed the source's threshold")
	require.False(t, r.lost(3, start.Add(1301*time.Millisecond), false), "non-eliciting packet cannot end the range")
	require.True(t, r.lost(4, start.Add(1302*time.Millisecond), true))
	unsampled := persistentLossRange{period: time.Second}
	require.False(t, unsampled.lost(0, start, true))
	require.False(t, unsampled.lost(1, start.Add(time.Hour), true))
}

func TestPersistentCongestionThroughRealACKAndLossHandling(t *testing.T) {
	for _, mode := range []string{"contiguous", "acknowledged-gap", "no-prior-sample"} {
		t.Run(mode, func(t *testing.T) {
			h := NewSentPacketHandler(0, 1257, utils.NewRTTStats(), new(utils.ConnectionStats), false, false, nil,
				protocol.PerspectiveClient, nil, utils.DefaultLogger, ClientSendConfig{
					SeparatePacketNumberSpaces: true, PersistentCongestionThreshold: 3,
					Congestion: congestion.SenderConfig{Algorithm: congestion.AlgorithmCubic, SlowStart: congestion.SlowStartClassic, InitialWindowPackets: 10},
				}).(*sentPacketHandler)
			h.packetNumbers(protocol.PacketNumberSpaceAppData).packetsUntilSkip = 1000
			var tracker packetTracker
			now := monotime.Now()
			sendInSpace(h, now, protocol.Encryption1RTT, &tracker)
			if mode != "no-prior-sample" {
				_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(0)}, protocol.Encryption1RTT, now.Add(100*time.Millisecond))
				require.NoError(t, err)
			}
			for _, delay := range []time.Duration{200, 800, 1400, 1800} {
				sendInSpace(h, now.Add(delay*time.Millisecond), protocol.Encryption1RTT, &tracker)
			}
			numbers := []protocol.PacketNumber{4}
			if mode == "acknowledged-gap" {
				numbers = append(numbers, 2)
			}
			_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(numbers...)}, protocol.Encryption1RTT, now.Add(1850*time.Millisecond))
			require.NoError(t, err)
			require.Zero(t, h.bytesInFlight)
			if mode == "contiguous" {
				require.EqualValues(t, 2*1257, h.congestion.GetCongestionWindow())
			} else {
				require.Greater(t, h.congestion.GetCongestionWindow(), protocol.ByteCount(2*1257), "an ACK gap or first RTT sample cannot establish persistent congestion")
			}
		})
	}
}
