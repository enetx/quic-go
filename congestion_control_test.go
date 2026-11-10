package quic

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCongestionControlValidationAndClone(t *testing.T) {
	for _, bad := range []*ClientHandshake{
		{CongestionControl: 255}, {SlowStart: 255}, {CongestionControlSegmentSize: 1199},
		{CongestionControlSegmentSize: 65528}, {CongestionControlConnections: 17},
		{CongestionControl: CongestionControlCubic, CongestionControlConnections: 2},
	} {
		require.Error(t, bad.Validate())
	}
	for _, h := range []*ClientHandshake{
		{}, {CongestionControl: CongestionControlReno, SlowStart: SlowStartClassic},
		{CongestionControl: CongestionControlCubic, SlowStart: SlowStartClassic, InitialCongestionWindowPackets: 10},
		{CongestionControl: CongestionControlCubicBytes, SlowStart: SlowStartHybrid, CongestionControlSegmentSize: 1460, CongestionControlConnections: 2},
	} {
		require.NoError(t, h.Validate())
		clone := h.Clone()
		require.Equal(t, h, clone)
		clone.CongestionControl = 255
		require.NotEqual(t, h.CongestionControl, clone.CongestionControl)
	}
	require.Zero(t, (&Config{}).congestionControlConfig())
}
