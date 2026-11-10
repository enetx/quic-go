package congestion

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestLeakyPacingOriginalNeqoVectors(t *testing.T) {
	var rows []struct {
		Scenario string
		NowNS    int64 `json:"now_ns"`
		RTTNS    int64 `json:"rtt_ns"`
		Cwnd     protocol.ByteCount
		NextNS   int64 `json:"next_ns"`
	}
	data, err := os.ReadFile("testdata/pacing_vectors.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &rows))
	var s *cubicSender
	var clock *mockClock
	start := monotime.Now()
	scenario := ""
	for i, row := range rows {
		if row.Scenario != scenario {
			s, clock = pacingSender(PacingLeakyBucket, time.Duration(row.RTTNS))
			*clock = mockClock(start)
			s.pacing.updated = start
			scenario = row.Scenario
		}
		if row.RTTNS == 0 {
			s.rttStats = new(utils.RTTStats)
		}
		s.congestionWindow = row.Cwnd
		*clock = mockClock(start.Add(time.Duration(row.NowNS)))
		s.pacing.sent(s, clock.Now(), 0, 1257, true)
		next := s.pacing.deadline(s, 0, clock.Now())
		var ns int64
		if !next.IsZero() && next > clock.Now() {
			ns = int64(next.Sub(start))
		}
		require.Equal(t, row.NextNS, ns, "row %d %s", i, row.Scenario)
	}
}

func TestPRROriginalQUICHEVectors(t *testing.T) {
	var rows []struct {
		Event   string
		Bytes   protocol.ByteCount
		Allowed []bool
	}
	data, err := os.ReadFile("testdata/prr_vectors.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &rows))
	var p prr
	p.lost(46720)
	for i, row := range rows {
		if row.Event == "s" {
			p.sent += row.Bytes
		} else {
			p.acked(row.Bytes)
		}
		for j, inFlight := range []protocol.ByteCount{0, 1000, 10000, 39712, 50000} {
			require.Equal(t, row.Allowed[j], p.canSend(39712, inFlight, 39712, 1460), "row %d flight %d", i, inFlight)
		}
	}
}
