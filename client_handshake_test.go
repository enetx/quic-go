package quic

import (
	"errors"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/quic-go/transportparams"
	"github.com/stretchr/testify/require"
)

func TestClientHandshakeStreamWindows(t *testing.T) {
	config := populateConfig(&Config{MaxStreamReceiveWindow: 1000, ClientHandshake: &ClientHandshake{StreamReceiveWindows: &StreamReceiveWindows{BidiLocal: 900, BidiRemote: 300, Uni: 0}, MaxDatagramFrameSize: 1200, TransportParameters: &transportparams.Layout{Order: []uint64{15, 5, 6, 7}}}})
	conn := &Conn{config: config, perspective: protocol.PerspectiveClient}
	p := &wire.TransportParameters{}
	conn.configureClientParameters(p)
	require.EqualValues(t, 900, p.InitialMaxStreamDataBidiLocal)
	require.EqualValues(t, 300, p.InitialMaxStreamDataBidiRemote)
	require.Zero(t, p.InitialMaxStreamDataUni)
	require.EqualValues(t, 1200, p.MaxDatagramFrameSize)
	for id, window := range map[protocol.StreamID]int{0: 900, 1: 300, 2: 0, 3: 0, 4: 900, 5: 300} {
		require.EqualValues(t, window, conn.initialStreamReceiveWindow(id))
	}
	conn.perspective = protocol.PerspectiveServer
	require.EqualValues(t, config.InitialStreamReceiveWindow, conn.initialStreamReceiveWindow(0))
}
func TestClientHandshakeConfigSnapshot(t *testing.T) {
	config := &Config{ClientHandshake: &ClientHandshake{StreamReceiveWindows: &StreamReceiveWindows{1, 2, 3}, TransportParameters: &transportparams.Layout{Order: []uint64{15}, Additional: []transportparams.Parameter{{ID: 100, Value: []byte{1}}}}}}
	clone := config.Clone()
	populated := populateConfig(config)
	config.ClientHandshake.StreamReceiveWindows.BidiLocal = 99
	config.ClientHandshake.TransportParameters.Order[0] = 5
	config.ClientHandshake.TransportParameters.Additional[0].Value[0] = 99
	for _, c := range []*Config{clone, populated} {
		require.EqualValues(t, 1, c.ClientHandshake.StreamReceiveWindows.BidiLocal)
		require.Equal(t, []uint64{15}, c.ClientHandshake.TransportParameters.Order)
		require.Equal(t, []byte{1}, c.ClientHandshake.TransportParameters.Additional[0].Value)
	}
}
func TestClientHandshakeValidation(t *testing.T) {
	for name, config := range map[string]*Config{
		"short-cid":           {ClientHandshake: &ClientHandshake{InitialDestinationConnectionIDLength: 7}},
		"large-cid":           {ClientHandshake: &ClientHandshake{InitialDestinationConnectionIDLength: 21}},
		"large-pn":            {ClientHandshake: &ClientHandshake{InitialPacketNumber: 1 << 62}},
		"datagrams-disabled":  {ClientHandshake: &ClientHandshake{MaxDatagramFrameSize: 1000}},
		"datagrams-large":     {EnableDatagrams: true, ClientHandshake: &ClientHandshake{MaxDatagramFrameSize: 1 << 62}},
		"stream-limit":        {MaxStreamReceiveWindow: 100, ClientHandshake: &ClientHandshake{StreamReceiveWindows: &StreamReceiveWindows{BidiLocal: 101}}},
		"duplicate-parameter": {ClientHandshake: &ClientHandshake{TransportParameters: &transportparams.Layout{Order: []uint64{4, 4}}}},
		"small-udp":           {ClientHandshake: &ClientHandshake{MaxUDPPayloadSize: 1199}},
		"large-udp":           {ClientHandshake: &ClientHandshake{MaxUDPPayloadSize: 65528}},
		"omitted-udp-limit":   {ClientHandshake: &ClientHandshake{OmitMaxUDPPayloadSize: true, MaxUDPPayloadSize: 1472}},
		"single-active-cid":   {ClientHandshake: &ClientHandshake{ActiveConnectionIDLimit: 1}},
		"active-cid-overflow": {ClientHandshake: &ClientHandshake{ActiveConnectionIDLimit: 1 << 62}},
		"fractional-ack":      {ClientHandshake: &ClientHandshake{MaxAckDelay: time.Millisecond + time.Nanosecond}},
		"negative-ack":        {ClientHandshake: &ClientHandshake{MaxAckDelay: -time.Millisecond}},
		"large-ack":           {ClientHandshake: &ClientHandshake{MaxAckDelay: 1 << 14 * time.Millisecond}},
	} {
		t.Run(name, func(t *testing.T) { require.Error(t, validateConfig(config)) })
	}
	for _, size := range []int{8, 12, 20} {
		c := &Config{ClientHandshake: &ClientHandshake{InitialDestinationConnectionIDLength: size}}
		require.NoError(t, validateConfig(c))
		a, err := c.initialDestinationConnectionID()
		require.NoError(t, err)
		b, err := c.initialDestinationConnectionID()
		require.NoError(t, err)
		require.Equal(t, size, a.Len())
		require.NotEqual(t, a, b)
	}
}

func TestClientHandshakeDatagramLimitValidation(t *testing.T) {
	for _, config := range []*Config{
		{ClientHandshake: &ClientHandshake{MaxDatagramFrameSize: 1}},
		{EnableDatagrams: true, ClientHandshake: &ClientHandshake{MaxDatagramFrameSize: quicvarint.Max + 1}},
	} {
		require.EqualError(t, validateConfig(config), "custom datagram limit requires enabled datagrams and must not exceed 4611686018427387903")
	}
	require.NoError(t, validateConfig(&Config{EnableDatagrams: true, ClientHandshake: &ClientHandshake{MaxDatagramFrameSize: quicvarint.Max}}))
}

func TestInitialPacketNumberFactory(t *testing.T) {
	config := &Config{}
	pn, err := config.initialPacketNumber()
	require.NoError(t, err)
	require.Zero(t, pn)
	count := uint64(0)
	config.ClientHandshake = &ClientHandshake{InitialPacketNumber: 5, NewInitialPacketNumber: func() (uint64, error) {
		count++
		return count, nil
	}}
	for _, want := range []uint64{1, 2} {
		pn, err := config.Clone().initialPacketNumber()
		require.NoError(t, err)
		require.EqualValues(t, want, pn)
	}
	config.ClientHandshake.NewInitialPacketNumber = func() (uint64, error) { return 1 << 62, nil }
	_, err = config.initialPacketNumber()
	require.Error(t, err)
	sentinel := errors.New("random source failed")
	config.ClientHandshake.NewInitialPacketNumber = func() (uint64, error) { return 0, sentinel }
	_, err = config.initialPacketNumber()
	require.ErrorIs(t, err, sentinel)
}

// A QUIC ClientHello can contain ECH without SNI, for example for an IP origin.
// Invalid SNI cuts must sort after real cuts or HasData stalls the handshake.
func TestInitialCryptoECHWithoutSNI(t *testing.T) {
	hello := []byte{1, 0, 0, 0, 3, 3}
	hello = append(hello, make([]byte, 32)...)
	hello = append(hello, 0, 0, 2, 0x13, 1, 1, 0, 0, 4, 0xfe, 0x0d, 0, 0)
	n := len(hello) - 4
	hello[1] = byte(n >> 16)
	hello[2] = byte(n >> 8)
	hello[3] = byte(n)
	stream := newInitialCryptoStream(true)
	stream.scramble = true
	_, err := stream.Write(hello)
	require.NoError(t, err)
	require.True(t, stream.HasData())
	got := make([]byte, len(hello))
	total := 0
	for i := 0; stream.HasData() && i < 20; i++ {
		frame := stream.PopCryptoFrame(100)
		require.NotNil(t, frame)
		copy(got[frame.Offset:], frame.Data)
		total += len(frame.Data)
	}
	require.False(t, stream.HasData())
	require.Equal(t, len(hello), total)
	require.Equal(t, hello, got)
}
