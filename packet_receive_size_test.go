package quic

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/enetx/quic-go/transportparams"
	"github.com/stretchr/testify/require"
)

func TestConfiguredReceivePacketSize(t *testing.T) {
	for _, basic := range []bool{false, true} {
		t.Run(map[bool]string{false: "oob", true: "basic"}[basic], func(t *testing.T) {
			socket := newUDPConnLocalhost(t)
			var packet net.PacketConn = socket
			if basic {
				packet = struct{ net.PacketConn }{socket}
			}
			conn, err := wrapConn(packet, 1472)
			require.NoError(t, err)
			defer conn.Close()
			sender := newUDPConnLocalhost(t)
			_, err = sender.WriteTo(make([]byte, 1472), socket.LocalAddr())
			require.NoError(t, err)
			socket.SetReadDeadline(time.Now().Add(time.Second))
			received, err := conn.ReadPacket()
			require.NoError(t, err)
			require.Len(t, received.data, 1472)
			received.buffer.Release()
		})
	}
	buffer := receivePacketBuffer(0)
	require.Len(t, buffer.Data, protocol.MaxPacketBufferSize)
	buffer.Release()
	// Omitting the UDP limit advertises the protocol's 65527-byte default.
	// Both pooled receive paths must retain their requested length on reuse.
	for range 2 {
		for _, size := range []int{1472, protocol.MaxLargePacketBufferSize, MaxUDPReceivePacketSize} {
			buffer := receivePacketBuffer(size)
			require.Len(t, buffer.Data, size)
			buffer.Release()
		}
	}
	require.Error(t, validateReceivePacketSize(1199))
	require.Error(t, validateReceivePacketSize(MaxUDPReceivePacketSize+1))
	config := &Config{ClientHandshake: &ClientHandshake{MaxUDPPayloadSize: 1472}}
	require.Error(t, (&Transport{}).validateReceiveLimit(config))
	require.NoError(t, (&Transport{ReceivePacketSize: 1472}).validateReceiveLimit(config))
	require.NoError(t, (&Transport{}).validateReceiveLimit(nil))
	config.ClientHandshake = &ClientHandshake{OmitMaxUDPPayloadSize: true}
	require.Error(t, (&Transport{ReceivePacketSize: 1472}).validateReceiveLimit(config))
	require.NoError(t, (&Transport{ReceivePacketSize: MaxUDPReceivePacketSize}).validateReceiveLimit(config))
}

func TestJumboUDPReceive(t *testing.T) {
	for _, basic := range []bool{false, true} {
		t.Run(map[bool]string{false: "oob", true: "basic"}[basic], func(t *testing.T) {
			socket := newUDPConnLocalhost(t)
			var packet net.PacketConn = socket
			if basic {
				packet = struct{ net.PacketConn }{socket}
			}
			// Keep the payload below macOS's default 9216-byte UDP send limit.
			// The receive path still provisions and returns a jumbo pooled buffer.
			conn, err := wrapConn(packet, MaxUDPReceivePacketSize)
			require.NoError(t, err)
			defer conn.Close()
			sender := newUDPConnLocalhost(t)
			_, err = sender.WriteTo(make([]byte, 8192), socket.LocalAddr())
			require.NoError(t, err)
			socket.SetReadDeadline(time.Now().Add(time.Second))
			received, err := conn.ReadPacket()
			require.NoError(t, err)
			require.Len(t, received.data, 8192)
			received.buffer.Release()
		})
	}
}

func TestConfiguredDatagramFrameReceiveLimit(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, nil)
	conn := &Conn{perspective: protocol.PerspectiveClient, config: &Config{}, datagramQueue: queue}
	frame := &wire.DatagramFrame{Data: make([]byte, 20000)}
	// The native limit remains enforced when no override is supplied.
	require.Error(t, conn.handleDatagramFrame(frame))
	conn.config.ClientHandshake = &ClientHandshake{MaxDatagramFrameSize: 65536}
	require.NoError(t, conn.handleDatagramFrame(frame))
	require.Len(t, queue.rcvQueue, 1)
	require.Equal(t, frame.Data, queue.rcvQueue[0])
	conn.config.ClientHandshake.MaxDatagramFrameSize = 20000
	// The wire frame type byte also counts towards the advertised limit.
	require.Error(t, conn.handleDatagramFrame(frame))
}
func TestClientWireControlsStayCoupled(t *testing.T) {
	config := populateConfig(&Config{EnableDatagrams: true, ClientHandshake: &ClientHandshake{MaxUDPPayloadSize: 1472, MaxDatagramFrameSize: 65536, ActiveConnectionIDLimit: 2, MaxAckDelay: 25 * time.Millisecond}})
	require.NoError(t, validateConfig(config))
	conn := &Conn{config: config, perspective: protocol.PerspectiveClient, connIDManager: &connIDManager{}}
	params := &wire.TransportParameters{}
	conn.configureClientParameters(params)
	require.EqualValues(t, 1472, params.MaxUDPPayloadSize)
	require.EqualValues(t, 65536, params.MaxDatagramFrameSize)
	require.EqualValues(t, 2, params.ActiveConnectionIDLimit)
	require.Equal(t, 25*time.Millisecond, params.MaxAckDelay)
	require.EqualValues(t, 2, conn.connIDManager.activeConnectionIDLimit())
	require.EqualValues(t, 65536, conn.maxReceiveDatagramFrameSize())
	// The manager now enforces the lower advertised limit, rather than merely
	// changing its serialized parameter. One queued ID + active ID is allowed.
	manager := newConnIDManager(protocol.ParseConnectionID([]byte{1}), func(protocol.StatelessResetToken) {}, func(protocol.StatelessResetToken) {}, func(wire.Frame) {})
	manager.activeIDLimit = 2
	require.NoError(t, manager.Add(&wire.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: protocol.ParseConnectionID([]byte{2})}))
	require.Error(t, manager.Add(&wire.NewConnectionIDFrame{SequenceNumber: 2, ConnectionID: protocol.ParseConnectionID([]byte{3})}))
}
func TestClientParameterFactoryPerAttempt(t *testing.T) {
	var versions []Version
	config := populateConfig(&Config{ClientHandshake: &ClientHandshake{NewTransportParameters: func(version Version) (*transportparams.Layout, error) {
		versions = append(versions, version)
		return &transportparams.Layout{Order: []uint64{15, 4}}, nil
	}}})
	conn := &Conn{config: config, version: Version1}
	params := &wire.TransportParameters{}
	require.Nil(t, conn.configureClientHandshake(params))
	require.Equal(t, []uint64{15, 4}, params.ClientLayout.Order)
	conn.version = Version2
	require.Nil(t, conn.configureClientHandshake(params))
	require.Equal(t, []Version{Version1, Version2}, versions)
	sentinel := errors.New("bad external parameters")
	config.ClientHandshake.NewTransportParameters = func(Version) (*transportparams.Layout, error) { return nil, sentinel }
	factory := conn.configureClientHandshake(params)
	require.NotNil(t, factory)
	_, err := factory(&tls.Config{})
	require.ErrorIs(t, err, sentinel)
	config.ClientHandshake.NewTransportParameters = func(Version) (*transportparams.Layout, error) {
		return &transportparams.Layout{Order: []uint64{4, 4}}, nil
	}
	factory = conn.configureClientHandshake(params)
	require.NotNil(t, factory)
	_, err = factory(&tls.Config{})
	require.Error(t, err)
}
