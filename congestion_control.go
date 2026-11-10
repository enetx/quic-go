package quic

import "github.com/enetx/quic-go/internal/congestion"

type CongestionControlAlgorithm = congestion.Algorithm
type SlowStartAlgorithm = congestion.SlowStart

const (
	CongestionControlNative     = congestion.AlgorithmNative
	CongestionControlReno       = congestion.AlgorithmReno
	CongestionControlCubic      = congestion.AlgorithmCubic
	CongestionControlCubicBytes = congestion.AlgorithmCubicBytes
	SlowStartNative             = congestion.SlowStartNative
	SlowStartClassic            = congestion.SlowStartClassic
	SlowStartHybrid             = congestion.SlowStartHybrid
)
