package quic

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestClientInitialRTTEstimate(t *testing.T) {
	for _, estimate := range []time.Duration{0, 17 * time.Millisecond, 800 * time.Millisecond} {
		h := &ClientHandshake{InitialRTT: estimate}
		require.NoError(t, h.Validate())
		require.Equal(t, estimate, h.Clone().InitialRTT)
		conn := newClientTestConnection(t, nil, &Config{ClientHandshake: h, DisablePathMTUDiscovery: true}, false).conn
		want := estimate
		if want == 0 {
			want = 100 * time.Millisecond
		}
		require.Equal(t, want, conn.rttStats.SmoothedRTT())
		require.Equal(t, 2*want, conn.rttStats.PTO(false))
		require.False(t, conn.rttStats.HasMeasurement())
		require.False(t, conn.ConnectionStats().RTTMeasured)
	}
	for _, estimate := range []time.Duration{-1, 1 << 62} {
		require.Error(t, (&ClientHandshake{InitialRTT: estimate}).Validate())
	}
	h := &ClientHandshake{InitialRTT: 11 * time.Millisecond, InitialPTOMultiplier: 3}
	conn := newClientTestConnection(t, nil, &Config{ClientHandshake: h, DisablePathMTUDiscovery: true}, false).conn
	require.Equal(t, 33*time.Millisecond, conn.rttStats.PTO(false))
	require.Equal(t, uint32(3), h.Clone().InitialPTOMultiplier)
	require.Error(t, (&ClientHandshake{InitialPTOMultiplier: 17}).Validate())
	conn.rttStats.UpdateRTT(time.Millisecond, 0)
	for range 100 {
		conn.rttStats.UpdateRTT(time.Millisecond, 0)
	}
	require.True(t, conn.ConnectionStats().RTTMeasured)
	require.Zero(t, conn.ConnectionStats().MeanDeviation, "zero variance is still a real measurement")
}
