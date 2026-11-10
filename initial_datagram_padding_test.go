package quic

import (
	"bytes"
	"testing"

	"github.com/enetx/quic-go/internal/handshake"
	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/qerr"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestInitialDatagramPaddingSerialization(t *testing.T) {
	for _, kind := range []string{"crypto", "pto", "close"} {
		t.Run(kind, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
			tp.packer.initialPaddingMode = InitialPaddingDatagram
			tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(ctrl), nil)
			tp.pnManager.EXPECT().PeekPacketNumber(protocol.PacketNumberSpaceInitial).Return(protocol.PacketNumber(0), protocol.PacketNumberLen1)
			tp.pnManager.EXPECT().PopPacketNumber(protocol.PacketNumberSpaceInitial).Return(protocol.PacketNumber(0))
			var packet *coalescedPacket
			var err error
			if kind == "close" {
				tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				tp.sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				packet, err = tp.packer.PackConnectionClose(&qerr.TransportError{ErrorCode: qerr.InternalError}, 1252, protocol.Version1)
			} else {
				tp.initialStream.scramble = false
				tp.initialStream.Write(bytes.Repeat([]byte{42}, 200))
				tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), false)
				if kind == "pto" {
					packet, err = tp.packer.PackPTOProbePacket(protocol.EncryptionInitial, 1252, false, monotime.Now(), protocol.Version1)
				} else {
					tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
					tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
					tp.sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
					packet, err = tp.packer.PackCoalescedPacket(false, 1252, monotime.Now(), protocol.Version1)
				}
			}
			require.NoError(t, err)
			defer packet.buffer.Release()
			require.EqualValues(t, 1252, packet.buffer.Len())
			headers, tail := parsePacket(t, packet.buffer.Data)
			require.Len(t, headers, 1)
			require.Greater(t, len(tail), 900)
			require.Equal(t, make([]byte, len(tail)), tail)
			require.EqualValues(t, len(tail), packet.initialDatagramPadding)
			require.Equal(t, packet.buffer.Len()-packet.initialDatagramPadding, packet.longHdrPackets[0].length)
		})
	}
}

func TestHandshakeAckPrecedesCrypto(t *testing.T) {
	ctrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
	tp.packer.handshakeAckBeforeData = true
	tp.packer.initialPaddingMode = InitialPaddingDatagram
	body := bytes.Repeat([]byte{42}, 36)
	tp.handshakeStream.Write(body)
	now := monotime.Now()
	ack := func() *wire.AckFrame { return &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}} }
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(ctrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(ctrl), nil)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, now, true).Return(ack())
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, now, true).Return(ack())
	for _, space := range []protocol.PacketNumberSpace{protocol.PacketNumberSpaceInitial, protocol.PacketNumberSpaceHandshake} {
		tp.pnManager.EXPECT().PeekPacketNumber(space).Return(protocol.PacketNumber(0), protocol.PacketNumberLen1)
		tp.pnManager.EXPECT().PopPacketNumber(space).Return(protocol.PacketNumber(0))
	}
	prefix, err := tp.packer.PackCoalescedPacket(false, 1252, now, protocol.Version1)
	require.NoError(t, err)
	defer prefix.buffer.Release()
	require.Len(t, prefix.longHdrPackets, 2)
	require.Nil(t, prefix.shortHdrPacket, "application data escaped into the prefix")
	for _, p := range prefix.longHdrPackets {
		require.NotNil(t, p.ack)
		require.Empty(t, p.frames)
	}
	require.True(t, tp.handshakeStream.HasData(), "local CRYPTO was consumed by ACK flight")
	headers, tail := parsePacket(t, prefix.buffer.Data)
	require.Len(t, headers, 2)
	require.Equal(t, make([]byte, len(tail)), tail)
	// Sending the Handshake ACK makes the connection dispose of Initial keys.
	tp.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(ctrl), nil)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, now, false)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PacketNumberSpaceHandshake).Return(protocol.PacketNumber(1), protocol.PacketNumberLen1)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PacketNumberSpaceHandshake).Return(protocol.PacketNumber(1))
	finished, err := tp.packer.PackCoalescedPacket(false, 1252, now, protocol.Version1)
	require.NoError(t, err)
	defer finished.buffer.Release()
	require.Len(t, finished.longHdrPackets, 1)
	require.Equal(t, protocol.EncryptionHandshake, finished.longHdrPackets[0].EncryptionLevel())
	require.Zero(t, finished.initialDatagramPadding)
	require.Less(t, finished.buffer.Len(), protocol.ByteCount(200))
	require.Equal(t, body, finished.longHdrPackets[0].frames[0].Frame.(*wire.CryptoFrame).Data)
	require.False(t, tp.handshakeStream.HasData())
}

func TestInitialDatagramPaddingRespectsPacketBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name           string
		perspective    protocol.Perspective
		mode           InitialPaddingMode
		initial, short bool
		pad            int
	}{
		{"native", protocol.PerspectiveClient, InitialPaddingPacket, true, false, 0},
		{"server", protocol.PerspectiveServer, InitialPaddingDatagram, true, false, 0},
		{"handshake-only", protocol.PerspectiveClient, InitialPaddingDatagram, false, false, 0},
		{"initial", protocol.PerspectiveClient, InitialPaddingDatagram, true, false, 1152},
		{"short-header", protocol.PerspectiveClient, InitialPaddingDatagram, true, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &packetPacker{perspective: tc.perspective, initialPaddingMode: tc.mode}
			buffer := getPacketBuffer()
			defer buffer.Release()
			buffer.Data = append(buffer.Data, make([]byte, 100)...)
			packet := &coalescedPacket{buffer: buffer}
			if tc.initial {
				packet.longHdrPackets = []*longHeaderPacket{{header: &wire.ExtendedHeader{Header: wire.Header{Type: protocol.PacketTypeInitial}}}}
			}
			if tc.short {
				packet.shortHdrPacket = &shortHeaderPacket{}
			}
			p.padInitialDatagram(packet, 1252)
			require.EqualValues(t, 100+tc.pad, buffer.Len())
			require.EqualValues(t, tc.pad, packet.initialDatagramPadding)
			padding := p.initialShortHeaderPadding(tc.initial, 100, 1252)
			if tc.perspective == protocol.PerspectiveClient && tc.mode == InitialPaddingDatagram && tc.initial {
				require.EqualValues(t, 1152, padding)
			} else {
				require.Zero(t, padding)
			}
		})
	}
}
