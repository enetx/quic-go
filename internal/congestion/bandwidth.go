package congestion

import (
	"math"
	"math/bits"
	"time"

	"github.com/enetx/quic-go/internal/protocol"
)

// Bandwidth of a connection
type Bandwidth uint64

const (
	// BitsPerSecond is 1 bit per second
	BitsPerSecond Bandwidth = 1
	// BytesPerSecond is 1 byte per second
	BytesPerSecond = 8 * BitsPerSecond
)

// BandwidthFromDelta calculates the bandwidth from a number of bytes and a time delta
func BandwidthFromDelta(bytes protocol.ByteCount, delta time.Duration) Bandwidth {
	if bytes <= 0 || delta <= 0 {
		return 0
	}
	// Preserve byte-per-second rounding, without overflowing at large windows.
	hi, lo := bits.Mul64(uint64(bytes), uint64(time.Second))
	if hi >= uint64(delta) {
		return Bandwidth(math.MaxUint64 / uint64(BytesPerSecond) * uint64(BytesPerSecond))
	}
	q, _ := bits.Div64(hi, lo, uint64(delta))
	if q > math.MaxUint64/uint64(BytesPerSecond) {
		q = math.MaxUint64 / uint64(BytesPerSecond)
	}
	return Bandwidth(q) * BytesPerSecond
}
