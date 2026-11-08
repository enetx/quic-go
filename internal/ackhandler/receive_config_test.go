package ackhandler

import (
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestConfiguredAckDelaySchedulesAlarm(t *testing.T) {
	for _, delay := range []time.Duration{0, 20 * time.Millisecond, 40 * time.Millisecond} {
		handler := NewReceivedPacketHandler(utils.DefaultLogger)
		handler.SetMaxAckDelay(delay)
		now := monotime.Now()
		require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.Encryption1RTT, now, false))
		require.NoError(t, handler.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption1RTT, now, true))
		want := delay
		if want == 0 {
			want = MaxAckDelay
		}
		require.Equal(t, now.Add(want), handler.GetAlarmTimeout())
	}
}
