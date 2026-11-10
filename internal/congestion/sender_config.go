package congestion

import (
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/enetx/quic-go/qlogwriter"
)

// Algorithm selects the congestion avoidance calculation, independently of pacing.
type Algorithm uint8

const (
	AlgorithmNative Algorithm = iota // Reno, as in upstream quic-go.
	AlgorithmReno
	AlgorithmCubic      // RFC 9438, with whole-segment growth credit.
	AlgorithmCubicBytes // Fixed-point byte-mode CUBIC.
)

type SlowStart uint8

const (
	SlowStartNative  SlowStart = iota // Upstream's original HyStart, not HyStart++.
	SlowStartClassic                  // Grow by acknowledged bytes until congestion.
	SlowStartHybrid                   // Original HyStart, growing by one segment per ACKed packet.
)

// SenderConfig contains mechanisms only. The application selects its policy.
type SenderConfig struct {
	Algorithm            Algorithm
	SlowStart            SlowStart
	InitialWindowPackets uint32
	// SegmentSize fixes the accounting segment independently of the path MTU.
	// Zero follows the MTU. Connections applies only to byte-mode CUBIC.
	SegmentSize uint16
	Connections uint32
}

func NewConfiguredSender(clock Clock, rtt *utils.RTTStats, stats *utils.ConnectionStats, mtu protocol.ByteCount, config SenderConfig, logger qlogwriter.Recorder) *cubicSender {
	segment := mtu
	if config.SegmentSize != 0 {
		segment = protocol.ByteCount(config.SegmentSize)
	}
	s := NewCubicSender(clock, rtt, stats, segment, config.Algorithm <= AlgorithmReno, logger, config.InitialWindowPackets)
	s.maxDatagramSize = mtu
	s.fixedSegmentSize = protocol.ByteCount(config.SegmentSize)
	s.classicSlowStart = config.SlowStart == SlowStartClassic
	if config.Algorithm == AlgorithmCubic {
		s.rfcCubic = new(rfcCubic)
	}
	if config.Algorithm == AlgorithmCubicBytes {
		s.cubic.segmentSize = segment
		if config.Connections != 0 {
			s.cubic.SetNumConnections(int(config.Connections))
		}
	}
	return s
}

func (c *cubicSender) segmentSize() protocol.ByteCount {
	if c.fixedSegmentSize != 0 {
		return c.fixedSegmentSize
	}
	return c.maxDatagramSize
}
