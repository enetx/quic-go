package quic

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/quic-go/tlsquic"
	"github.com/enetx/quic-go/transportparams"
)

// StreamReceiveWindows overrides the three initial receive windows independently.
// Local and Remote describe the initiator relative to this client. Zero explicitly
// advertises zero credit. The runtime flow controllers use the same values.
type StreamReceiveWindows struct{ BidiLocal, BidiRemote, Uni uint64 }

// ClientHandshake exposes client-only protocol controls. Nil preserves upstream
// behavior. It contains no browser defaults or preset selection. Extension values
// and TLS templates are supplied by the application. Server behavior is unchanged.
type ClientHandshake struct {
	// NewInitialPacketNumber selects a fresh start for each new connection.
	NewInitialPacketNumber func() (uint64, error)
	// OmitMaxUDPPayloadSize selects the protocol default and requires a matching receive buffer.
	OmitMaxUDPPayloadSize bool
	// OmitLegacyResetStreamAt advertises only the current reliable-reset parameter.
	OmitLegacyResetStreamAt bool

	// NewTransportParameters produces a private layout for every handshake attempt,
	// including a restart after version negotiation. It receives the actual version.
	NewTransportParameters func(Version) (*transportparams.Layout, error)

	// MaxUDPPayloadSize must fit Transport.ReceivePacketSize. Zero preserves native.
	MaxUDPPayloadSize uint64
	// ActiveConnectionIDLimit sets the receive-side connection ID limit (at least 2).
	ActiveConnectionIDLimit uint64
	// MaxAckDelay sets the acknowledgment scheduling bound.
	// The protocol default is omitted automatically by the transport codec.
	MaxAckDelay time.Duration
	// AckPolicy controls local Application Data ACK scheduling. Nil keeps native behavior.
	AckPolicy *AckPolicy

	// DisableClientHelloScrambling disables upstream SNI/ECH CRYPTO fragmentation.
	DisableClientHelloScrambling bool

	StreamReceiveWindows *StreamReceiveWindows
	TransportParameters  *transportparams.Layout
	NewTLSClient         tlsquic.NewClient
	// MaxDatagramFrameSize overrides the advertised limit when datagrams are
	// enabled. Zero preserves upstream; values must fit a QUIC integer.
	MaxDatagramFrameSize uint64
	// InitialDestinationConnectionIDLength, when nonzero, must be 8 through 20.
	InitialDestinationConnectionIDLength int
	// InitialPacketNumber is used on the first connection attempt only.
	InitialPacketNumber uint64
}

// Clone snapshots mutable configuration while retaining callback identity.
func (h *ClientHandshake) Clone() *ClientHandshake {
	if h == nil {
		return nil
	}
	c := *h
	c.AckPolicy = h.AckPolicy.Clone()
	if h.StreamReceiveWindows != nil {
		w := *h.StreamReceiveWindows
		c.StreamReceiveWindows = &w
	}
	c.TransportParameters = h.TransportParameters.Clone()
	return &c
}
func (c *Config) validateClientHandshake() error {
	h := c.ClientHandshake
	if h == nil {
		return nil
	}
	if h.MaxUDPPayloadSize != 0 && (h.MaxUDPPayloadSize < 1200 || h.MaxUDPPayloadSize > MaxUDPReceivePacketSize) {
		return fmt.Errorf("max UDP payload size exceeds receive buffer support")
	}
	if h.ActiveConnectionIDLimit != 0 && (h.ActiveConnectionIDLimit < 2 || h.ActiveConnectionIDLimit > quicvarint.Max) {
		return fmt.Errorf("active connection ID limit outside protocol range")
	}
	if h.MaxAckDelay != 0 && (h.MaxAckDelay < time.Millisecond || h.MaxAckDelay > protocol.MaxMaxAckDelay || h.MaxAckDelay%time.Millisecond != 0) {
		return fmt.Errorf("max ACK delay must be a whole number of milliseconds within the protocol range")
	}
	if err := h.AckPolicy.Validate(h.MaxAckDelay); err != nil {
		return err
	}
	if h.OmitMaxUDPPayloadSize && h.MaxUDPPayloadSize != 0 && h.MaxUDPPayloadSize != MaxUDPReceivePacketSize {
		return fmt.Errorf("omitted UDP payload size must use protocol default")
	}
	if err := h.TransportParameters.Validate(); err != nil {
		return err
	}
	if n := h.InitialDestinationConnectionIDLength; n != 0 && (n < 8 || n > 20) {
		return fmt.Errorf("initial destination connection ID length must be 8 through 20: %d", n)
	}
	if h.InitialPacketNumber > quicvarint.Max {
		return fmt.Errorf("initial packet number exceeds QUIC range")
	}
	if h.MaxDatagramFrameSize > 0 && (!c.EnableDatagrams || h.MaxDatagramFrameSize > quicvarint.Max) {
		return fmt.Errorf("custom datagram limit requires enabled datagrams and must not exceed %d", quicvarint.Max)
	}
	if w := h.StreamReceiveWindows; w != nil {
		limit := c.MaxStreamReceiveWindow
		if limit == 0 {
			limit = uint64(protocol.DefaultMaxReceiveStreamFlowControlWindow)
		}
		for _, v := range []uint64{w.BidiLocal, w.BidiRemote, w.Uni} {
			if v > quicvarint.Max || v > limit {
				return fmt.Errorf("initial stream receive window %d exceeds maximum %d", v, limit)
			}
		}
	}
	return nil
}
func (c *Config) clientTLSFactory() tlsquic.NewClient {
	if c.ClientHandshake == nil {
		return nil
	}
	return c.ClientHandshake.NewTLSClient
}
func (c *Conn) configureClientParameters(p *wire.TransportParameters) {
	h := c.config.ClientHandshake
	if h == nil {
		return
	}
	if h.MaxUDPPayloadSize > 0 {
		p.MaxUDPPayloadSize = protocol.ByteCount(h.MaxUDPPayloadSize)
	}
	if h.ActiveConnectionIDLimit > 0 {
		p.ActiveConnectionIDLimit = h.ActiveConnectionIDLimit
		c.connIDManager.activeIDLimit = h.ActiveConnectionIDLimit
	}
	if h.MaxAckDelay > 0 {
		p.MaxAckDelay = h.MaxAckDelay
		c.receivedPacketHandler.SetMaxAckDelay(h.MaxAckDelay)
	}
	c.receivedPacketHandler.SetAckPolicy(h.AckPolicy, c.rttStats)
	if w := h.StreamReceiveWindows; w != nil {
		p.InitialMaxStreamDataBidiLocal = protocol.ByteCount(w.BidiLocal)
		p.InitialMaxStreamDataBidiRemote = protocol.ByteCount(w.BidiRemote)
		p.InitialMaxStreamDataUni = protocol.ByteCount(w.Uni)
	}
	if h.MaxDatagramFrameSize > 0 {
		p.MaxDatagramFrameSize = protocol.ByteCount(h.MaxDatagramFrameSize)
	}
	if h.OmitMaxUDPPayloadSize {
		p.MaxUDPPayloadSize = MaxUDPReceivePacketSize
		p.OmitMaxUDPPayloadSize = true
	}
	p.OmitLegacyResetStreamAt = h.OmitLegacyResetStreamAt
	p.ClientLayout = h.TransportParameters
}
func (c *Conn) initialStreamReceiveWindow(id protocol.StreamID) protocol.ByteCount {
	if c.perspective == protocol.PerspectiveClient && c.config.ClientHandshake != nil {
		if w := c.config.ClientHandshake.StreamReceiveWindows; w != nil {
			if protocol.StreamTypeOf(id) == protocol.StreamTypeUni {
				return protocol.ByteCount(w.Uni)
			}
			if protocol.StreamInitiator(id) == c.perspective {
				return protocol.ByteCount(w.BidiLocal)
			}
			return protocol.ByteCount(w.BidiRemote)
		}
	}
	return protocol.ByteCount(c.config.InitialStreamReceiveWindow)
}
func (c *Config) initialDestinationConnectionID() (protocol.ConnectionID, error) {
	if c.ClientHandshake == nil || c.ClientHandshake.InitialDestinationConnectionIDLength == 0 {
		return generateConnectionIDForInitial()
	}
	b := make([]byte, c.ClientHandshake.InitialDestinationConnectionIDLength)
	if _, err := rand.Read(b); err != nil {
		return protocol.ConnectionID{}, err
	}
	return protocol.ParseConnectionID(b), nil
}
func (c *Config) initialPacketNumber() (protocol.PacketNumber, error) {
	if c.ClientHandshake == nil {
		return 0, nil
	}
	value := c.ClientHandshake.InitialPacketNumber
	if factory := c.ClientHandshake.NewInitialPacketNumber; factory != nil {
		var err error
		value, err = factory()
		if err != nil {
			return 0, err
		}
	}
	if value > quicvarint.Max {
		return 0, fmt.Errorf("initial packet number exceeds QUIC range")
	}
	return protocol.PacketNumber(value), nil
}

func (c *Conn) configureInitialCryptoStream() {
	if c.perspective == protocol.PerspectiveClient && c.config.ClientHandshake != nil && c.config.ClientHandshake.DisableClientHelloScrambling {
		c.initialStream.scramble = false
	}
}

func (h *connIDManager) activeConnectionIDLimit() uint64 {
	if h.activeIDLimit > 0 {
		return h.activeIDLimit
	}
	return protocol.MaxActiveConnectionIDs
}

func (c *Conn) configureClientHandshake(params *wire.TransportParameters) tlsquic.NewClient {
	c.configureClientParameters(params)
	h := c.config.ClientHandshake
	if h != nil && h.NewTransportParameters != nil {
		layout, err := h.NewTransportParameters(c.version)
		if err == nil {
			err = layout.Validate()
		}
		if err != nil {
			return func(*tls.Config) (tlsquic.Conn, error) { return nil, err }
		}
		params.ClientLayout = layout.Clone()
	}
	return c.config.clientTLSFactory()
}
