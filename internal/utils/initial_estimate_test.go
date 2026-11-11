package utils

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestExplicitInitialEstimate(t *testing.T) {
	r := NewRTTStats()
	r.SetInitialEstimate(11 * time.Millisecond)
	require.Equal(t, 11*time.Millisecond, r.MinRTT())
	require.Equal(t, 22*time.Millisecond, r.PTO(false))
	require.Zero(t, r.MeanDeviation())
	r.UpdateRTT(50*time.Millisecond, 0)
	require.Equal(t, 50*time.Millisecond, r.SmoothedRTT())
	require.Equal(t, 150*time.Millisecond, r.PTO(false))
	r.SetInitialEstimate(time.Second)
	require.Equal(t, 50*time.Millisecond, r.MinRTT())
	r.ResetForPathMigration()
	require.Equal(t, 2*DefaultInitialRTT, r.PTO(false))
	r.SetInitialEstimate(-1)
	require.Equal(t, DefaultInitialRTT, r.SmoothedRTT())
	r.SetInitialPTOMultiplier(5)
	require.Equal(t, 5*DefaultInitialRTT, r.PTO(false))
	r.UpdateRTT(20*time.Millisecond, 0)
	require.Equal(t, 60*time.Millisecond, r.PTO(false))
}

func TestInitialEstimateClone(t *testing.T) {
	r := NewRTTStats()
	r.SetInitialEstimate(11 * time.Millisecond)
	r.SetInitialPTOMultiplier(3)
	copy := r.Clone()
	require.Equal(t, 33*time.Millisecond, copy.PTO(false))
	require.False(t, copy.HasMeasurement())
	r.ResetForPathMigration()
	require.Equal(t, 33*time.Millisecond, copy.PTO(false))
}
