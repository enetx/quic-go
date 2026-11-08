package quic

import (
	"fmt"
	"sync"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
)

// receivePacketBuffer preserves the default pool and opts into the existing
// large-buffer pool only when the application requests a larger receive limit.
func receivePacketBuffer(size int) *packetBuffer {
	if size == 0 {
		size = protocol.MaxPacketBufferSize
	}
	var buffer *packetBuffer
	if size > protocol.MaxLargePacketBufferSize {
		buffer = getJumboReceivePacketBuffer()
	} else if size > protocol.MaxPacketBufferSize {
		buffer = getLargePacketBuffer()
	} else {
		buffer = getPacketBuffer()
	}
	buffer.Data = buffer.Data[:size]
	return buffer
}
func validateReceivePacketSize(size int) error {
	if size != 0 && (size < protocol.MinInitialPacketSize || size > MaxUDPReceivePacketSize) {
		return fmt.Errorf("QUIC receive packet size must be between %d and %d", protocol.MinInitialPacketSize, MaxUDPReceivePacketSize)
	}
	return nil
}
func (c *basicConn) setReadPacketSize(size int) { c.receivePacketSize = size }
func (t *Transport) validateReceiveLimit(config *Config) error {
	if config == nil {
		return nil
	}
	if h := config.ClientHandshake; h != nil && (h.MaxUDPPayloadSize > 0 || h.OmitMaxUDPPayloadSize) {
		size := t.ReceivePacketSize
		if size == 0 {
			size = protocol.MaxPacketBufferSize
		}
		required := h.MaxUDPPayloadSize
		if h.OmitMaxUDPPayloadSize {
			required = MaxUDPReceivePacketSize
		}
		if required > uint64(size) {
			return fmt.Errorf("advertised max_udp_payload_size %d exceeds transport receive size %d", h.MaxUDPPayloadSize, size)
		}
	}
	return nil
}
func (c *Conn) maxReceiveDatagramFrameSize() protocol.ByteCount {
	if c.perspective == protocol.PerspectiveClient && c.config != nil && c.config.ClientHandshake != nil && c.config.ClientHandshake.MaxDatagramFrameSize > 0 {
		return protocol.ByteCount(c.config.ClientHandshake.MaxDatagramFrameSize)
	}
	return wire.MaxDatagramSize
}

// MaxUDPReceivePacketSize is QUIC's default maximum UDP payload limit (RFC 9000).
// Applications omitting max_udp_payload_size must provision this receive size.
const MaxUDPReceivePacketSize = 65527

var jumboReceivePool = sync.Pool{New: func() any { return &packetBuffer{Data: make([]byte, 0, MaxUDPReceivePacketSize)} }}

func getJumboReceivePacketBuffer() *packetBuffer {
	buffer := jumboReceivePool.Get().(*packetBuffer)
	buffer.refCount = 1
	buffer.Data = buffer.Data[:0]
	return buffer
}
