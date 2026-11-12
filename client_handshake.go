package quic

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/enetx/quic-go/internal/ackhandler"
	"github.com/enetx/quic-go/internal/congestion"
	"github.com/enetx/quic-go/internal/monotime"
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
	// InitialRTT supplies a local estimate until the first RTT measurement.
	// Zero retains native initialization. It does not advertise a parameter.
	InitialRTT time.Duration
	// OnEarlyDataRejected observes a client's TLS 0-RTT rejection. It runs on
	// the connection loop; callbacks must return promptly and not reenter it.
	OnEarlyDataRejected func(*Conn)
	// InitialPTOMultiplier scales the initial estimate before any measurement.
	// Zero retains the native factor of two. Positive values are 1..16.
	InitialPTOMultiplier uint32
	// CompatibleVersionNegotiation enables RFC 9368 / RFC 9369 client switching
	// between v1 and v2, with authenticated downgrade checks. A layout can supply
	// version_information ordering and GREASE; otherwise Config.Versions is used.
	CompatibleVersionNegotiation bool
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
	// LegacyAckFrequencyMinDelay enables the legacy ACK_FREQUENCY receive
	// format and advertises its min_ack_delay (0xff02de1a). Zero disables it.
	// Positive values must be whole microseconds no larger than MaxAckDelay.
	LegacyAckFrequencyMinDelay time.Duration
	// PeerAckFrequencyPolicy opts into sending legacy ACK_FREQUENCY requests
	// after a peer advertises its legacy minimum. Nil sends no requests.
	PeerAckFrequencyPolicy PeerAckFrequencyPolicy
	// InitialCongestionWindowPackets selects the initial congestion window in
	// units of the accounting segment (the initial MTU unless fixed below).
	// Zero retains the native packet count.
	InitialCongestionWindowPackets uint32
	// MaxCongestionWindowPackets sets a ceiling in accounting segments. Zero keeps
	// the native 10000-segment ceiling; -1 removes that ceiling. Internal packet
	// history and integer safety limits still apply. Positive values are 2..2^32-1.
	MaxCongestionWindowPackets int64
	Pacing                     *PacingConfig
	ProportionalRateReduction  bool
	RecoveryBurstPackets       uint32
	// PersistentCongestionThreshold collapses the window after this many base
	// PTO durations of consecutively lost ack-eliciting packets. Zero disables it.
	PersistentCongestionThreshold uint32
	// CongestionControl selects Reno, RFC 9438 CUBIC, or fixed-point byte-mode
	// CUBIC. Zero retains native Reno. Pacing and loss detection are independent.
	CongestionControl CongestionControlAlgorithm
	// SlowStart selects classic byte growth or original HyStart (not HyStart++).
	SlowStart SlowStartAlgorithm
	// CongestionControlSegmentSize fixes the accounting segment independently of
	// path MTU. Zero follows the MTU; explicit values must fit 1200..65527.
	CongestionControlSegmentSize uint16
	// CongestionControlConnections selects 1..16 emulated connections for byte-mode
	// CUBIC. Zero means one. Other algorithms accept only zero or one.
	CongestionControlConnections uint32
	// ReceiveWindowUpdateDivisor refreshes credit after more than 1/divisor
	// of the receive window is consumed. Zero retains the native policy.
	ReceiveWindowUpdateDivisor uint32
	// AckOnlyPingThreshold counts consecutive ACK-only packets before adding
	// a PING. Zero retains native behavior; -1 disables these extra PINGs.
	AckOnlyPingThreshold int
	// AckOnlyMaxDataThreshold requests a repeat of the current connection credit
	// after this many ACK-only packets, instead of injecting a periodic PING.
	// Zero disables this policy. It never grants additional receive credit.
	AckOnlyMaxDataThreshold int
	// AckProbePolicy optionally adds PING to an otherwise ACK-only packet. It
	// replaces periodic probes. Callbacks must not block or reenter the connection.
	AckProbePolicy func(AckProbeInfo) bool
	// PacketNumberLengthPolicy chooses encoded packet-number bytes from a live
	// snapshot. Unsafe short results are increased; invalid results use native.
	PacketNumberLengthPolicy func(PacketNumberLengthInfo) uint8
	// DisableConnectionIDRotation retains the active ID on an unchanged path.
	// Peer-requested retirement and path migration still select a replacement.
	DisableConnectionIDRotation bool
	// SortConnectionIDFrames orders queued NEW_CONNECTION_ID frames by ascending
	// sequence number while preserving positions of other control-frame types.
	SortConnectionIDFrames bool
	// OnApplicationReady runs once after verified TLS and peer transport
	// parameters, before releasing HandshakeComplete and sending the next flight.
	// It must not block, reenter Dial, call CloseWithError or use blocking Write.
	// OpenUniStream and SendStream.TryWriteAll may be used to stage initial data.
	OnApplicationReady func(*Conn)
	// OmitInitialAckOnHandshake omits an ACK-only Initial when client
	// Handshake data is ready. Initial keys are discarded when Handshake sends.
	OmitInitialAckOnHandshake bool
	InitialPacketProtection   *InitialPacketProtection
	// InitialPaddingMode chooses encrypted packet padding or a zero datagram tail.
	InitialPaddingMode InitialPaddingMode
	// HandshakeAckBeforeData sends queued Initial/Handshake ACKs in a separate
	// datagram before the first local Handshake CRYPTO. It inserts no time delay
	// and does not alter TLS verification or native Initial key disposal.
	HandshakeAckBeforeData bool
	// NewInitialDestinationConnectionIDLength selects a fresh length (8..20).
	NewInitialDestinationConnectionIDLength func() (int, error)
	// NewInitialPacketSize selects the UDP payload floor from the actual remote
	// address for each dial attempt. Results must fit 1200..MaxPacketBufferSize.
	NewInitialPacketSize func(net.Addr) (uint16, error)

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
	// SeparatePacketNumberSpaces starts Handshake and Application Data at zero,
	// independently of Initial. 0-RTT and 1-RTT share Application Data.
	SeparatePacketNumberSpaces bool
	// DisablePacketNumberSkipping suppresses artificial Application Data gaps,
	// including PTO skips. The native skipped-ACK defense remains the default.
	DisablePacketNumberSkipping bool
}

// Clone snapshots mutable configuration while retaining callback identity.
func (h *ClientHandshake) Clone() *ClientHandshake {
	if h == nil {
		return nil
	}
	c := *h
	if h.Pacing != nil {
		p := *h.Pacing
		c.Pacing = &p
	}
	if h.InitialPacketProtection != nil {
		policy := *h.InitialPacketProtection
		c.InitialPacketProtection = &policy
	}
	c.AckPolicy = h.AckPolicy.Clone()
	if h.StreamReceiveWindows != nil {
		w := *h.StreamReceiveWindows
		c.StreamReceiveWindows = &w
	}
	c.TransportParameters = h.TransportParameters.Clone()
	return &c
}

// Validate checks standalone client controls without invoking per-attempt
// factories. Config validation additionally checks runtime window/datagram coupling.
func (h *ClientHandshake) Validate() error {
	if h == nil {
		return nil
	}
	if h.InitialPTOMultiplier > 16 {
		return fmt.Errorf("initial PTO multiplier must be between 1 and 16, or zero")
	}
	if h.InitialRTT < 0 || h.InitialRTT > time.Duration((1<<63-1)/16) {
		return fmt.Errorf("initial RTT must be nonnegative and fit probe timeout scaling")
	}
	if h.CongestionControl > CongestionControlCubicBytes || h.SlowStart > SlowStartHybrid {
		return fmt.Errorf("invalid congestion control or slow start algorithm")
	}
	if h.CongestionControlSegmentSize != 0 && (h.CongestionControlSegmentSize < 1200 || h.CongestionControlSegmentSize > 65527) {
		return fmt.Errorf("invalid congestion control segment size")
	}
	if h.CongestionControlConnections > 16 || h.CongestionControlConnections > 1 && h.CongestionControl != CongestionControlCubicBytes {
		return fmt.Errorf("invalid congestion control connection count")
	}
	if n := h.InitialCongestionWindowPackets; n != 0 && (n < 2 || n > protocol.MaxCongestionWindowPackets) {
		return fmt.Errorf("initial congestion window outside supported packet range")
	}
	if n := h.MaxCongestionWindowPackets; n < -1 || n == 1 || n > 1<<32-1 {
		return fmt.Errorf("invalid maximum congestion window")
	}
	initial := h.InitialCongestionWindowPackets
	if initial == 0 {
		initial = 32
	}
	if h.MaxCongestionWindowPackets > 0 && int64(initial) > h.MaxCongestionWindowPackets {
		return fmt.Errorf("initial congestion window exceeds maximum")
	}
	if h.RecoveryBurstPackets > 16 || h.PersistentCongestionThreshold > 16 {
		return fmt.Errorf("invalid congestion recovery policy")
	}
	if p := h.Pacing; p != nil {
		if p.Algorithm > PacingScheduled || p.Algorithm != PacingNative && (p.BurstPackets == 0 || p.BurstPackets > 10000 || p.LumpyPackets == 0 || p.LumpyPackets > 10000 || p.LumpyWindowFraction > 1000 || p.Granularity < 0 || p.Granularity > time.Second || p.SlowStartGain == 0 || p.SlowStartGain > 10000 || p.AvoidanceGain == 0 || p.AvoidanceGain > 10000) {
			return fmt.Errorf("invalid pacing policy")
		}
	}
	maximum := h.MaxAckDelay
	if maximum == 0 {
		maximum = ackhandler.MaxAckDelay
	}
	if h.LegacyAckFrequencyMinDelay < 0 || h.LegacyAckFrequencyMinDelay > 0 && (h.LegacyAckFrequencyMinDelay > maximum || h.LegacyAckFrequencyMinDelay%time.Microsecond != 0) {
		return fmt.Errorf("invalid legacy ACK_FREQUENCY minimum delay")
	}
	if h.InitialPaddingMode > InitialPaddingDatagram {
		return fmt.Errorf("invalid Initial padding mode: %d", h.InitialPaddingMode)
	}
	if h.ReceiveWindowUpdateDivisor == 1 || h.AckOnlyPingThreshold < -1 || h.AckOnlyMaxDataThreshold < 0 ||
		(h.AckOnlyMaxDataThreshold > 0 && h.AckOnlyPingThreshold > 0) ||
		(h.AckProbePolicy != nil && (h.AckOnlyMaxDataThreshold > 0 || h.AckOnlyPingThreshold > 0)) {
		return fmt.Errorf("invalid receive-window divisor or conflicting ACK probe policies")
	}
	if err := h.InitialPacketProtection.validate(); err != nil {
		return err
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
	return nil
}

func (c *Config) validateClientHandshake() error {
	h := c.ClientHandshake
	if err := h.Validate(); err != nil {
		return err
	}
	maximum := ackhandler.MaxAckDelay
	if h != nil && h.MaxAckDelay > 0 {
		maximum = h.MaxAckDelay
	}
	if minimum := c.LegacyAckFrequencyMinDelay; minimum < 0 || minimum > 0 &&
		(minimum > maximum || minimum%time.Microsecond != 0) {
		return fmt.Errorf("invalid legacy ACK_FREQUENCY minimum delay")
	}
	if h == nil {
		return nil
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

func (c *Config) clientSendConfig() ackhandler.ClientSendConfig {
	h := c.ClientHandshake
	if h == nil {
		return ackhandler.ClientSendConfig{}
	}
	return ackhandler.ClientSendConfig{
		Congestion: congestion.SenderConfig{
			Algorithm: h.CongestionControl, SlowStart: h.SlowStart,
			InitialWindowPackets: h.InitialCongestionWindowPackets, MaxWindowPackets: h.MaxCongestionWindowPackets,
			Pacing: h.Pacing, PRR: h.ProportionalRateReduction, RecoveryBurstPackets: h.RecoveryBurstPackets,
			SegmentSize: h.CongestionControlSegmentSize, Connections: h.CongestionControlConnections,
		},
		PersistentCongestionThreshold: h.PersistentCongestionThreshold,
		SeparatePacketNumberSpaces:    h.SeparatePacketNumberSpaces,
		DisablePacketNumberSkipping:   h.DisablePacketNumberSkipping,
	}
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
	h := c.ClientHandshake
	if h == nil || (h.InitialDestinationConnectionIDLength == 0 && h.NewInitialDestinationConnectionIDLength == nil) {
		return generateConnectionIDForInitial()
	}
	length := h.InitialDestinationConnectionIDLength
	if h.NewInitialDestinationConnectionIDLength != nil {
		var err error
		length, err = h.NewInitialDestinationConnectionIDLength()
		if err != nil {
			return protocol.ConnectionID{}, err
		}
	}
	if length < 8 || length > 20 {
		return protocol.ConnectionID{}, fmt.Errorf("Initial connection ID factory length outside 8..20: %d", length)
	}
	b := make([]byte, length)
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
	if h := c.config.ClientHandshake; c.perspective == protocol.PerspectiveClient && h != nil && h.InitialPacketProtection != nil {
		c.initialStream.scramble = false
		c.initialStream.protection = &initialProtectionState{policy: *h.InitialPacketProtection}
	}
}

func (c *Conn) configureClientPacketPacker() {
	if h := c.config.ClientHandshake; h != nil {
		c.connIDManager.disableRotation = h.DisableConnectionIDRotation
		c.framer.sortConnectionIDFrames = h.SortConnectionIDFrames
		ackhandler.SetPacketNumberLengthPolicy(c.sentPacketHandler, h.PacketNumberLengthPolicy)
		p := c.packer.(*packetPacker)
		if h.AckProbePolicy != nil {
			p.shouldProbeAckOnly = func(now monotime.Time) bool {
				return ackhandler.AckProbeNeeded(c.sentPacketHandler, now, h.AckProbePolicy)
			}
		}
		if h.CompatibleVersionNegotiation && c.compatibleVersion != nil {
			p.zeroRTTVersion = c.compatibleVersion.chosen
		}
		p.ackOnlyPingThreshold = h.AckOnlyPingThreshold
		p.omitInitialAckOnHandshake = h.OmitInitialAckOnHandshake
		p.initialProtection = h.InitialPacketProtection
		p.initialPaddingMode = h.InitialPaddingMode
		p.handshakeAckBeforeData = h.HandshakeAckBeforeData
		p.sortConnectionIDFrames = h.SortConnectionIDFrames
		p.ackOnlyMaxDataThreshold = h.AckOnlyMaxDataThreshold
		p.queueAckOnlyProbe = func() {
			c.connFlowController.mutex.Lock()
			credit := c.connFlowController.receiveWindow
			c.connFlowController.mutex.Unlock()
			c.queueControlFrame(&wire.MaxDataFrame{MaximumData: credit})
		}
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
	c.configureLegacyAckFrequency(params)
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
	if h != nil && h.CompatibleVersionNegotiation {
		if err := c.configureVersionInformation(params); err != nil {
			return func(*tls.Config) (tlsquic.Conn, error) { return nil, err }
		}
	}
	return c.config.clientTLSFactory()
}
