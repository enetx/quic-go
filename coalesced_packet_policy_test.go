package quic

import (
	"testing"

	"github.com/enetx/quic-go/internal/ackhandler"
	"github.com/enetx/quic-go/internal/handshake"
	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestCoalescedPacketNumberBudgetOnWire(t *testing.T) {
	ctrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
	handler := ackhandler.NewSentPacketHandler(1, 1250, utils.NewRTTStats(), &utils.ConnectionStats{}, false, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger)
	ackhandler.SetPacketNumberLengthPolicy(handler, func(info PacketNumberLengthInfo) uint8 {
		if info.CoalescedMaxPacketsInFlight > info.MaxPacketsInFlight {
			return 2
		}
		return 1
	})
	tp.packer.pnManager = handler
	tp.packer.coalescedPacketSize = func(space protocol.PacketNumberSpace, size protocol.ByteCount) {
		ackhandler.SetCoalescedPacketSize(handler, space, size)
	}
	hello, err := getClientHello("layout.quic-go.net")
	require.NoError(t, err)
	tp.initialStream.layout = func(info InitialCryptoLayoutInfo) [][]CryptoRange {
		if len(info.Remaining) != 1 || info.Remaining[0].Length != info.Length {
			return [][]CryptoRange{info.Remaining}
		}
		return [][]CryptoRange{{{Offset: len(hello) - 60, Length: 60}}, {{Offset: 0, Length: len(hello) - 60}}}
	}
	_, err = tp.initialStream.Write(hello)
	require.NoError(t, err)
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(ctrl), nil).Times(2)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable).Times(2)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable).Times(2)
	tp.sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable).Times(2)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), false).Return(nil).Times(2)
	for i, want := range []protocol.PacketNumberLen{1, 2} {
		packet, err := tp.packer.PackCoalescedPacket(false, 1250, monotime.Now(), protocol.Version1)
		require.NoError(t, err)
		headers, rest := parsePacket(t, packet.buffer.Data)
		require.Empty(t, rest)
		require.Len(t, headers, 1)
		require.EqualValues(t, i+1, headers[0].PacketNumber)
		require.Equal(t, want, headers[0].PacketNumberLen, "decoded wire width follows the live application policy")
		require.EqualValues(t, 1250, packet.buffer.Len(), "the temporary limit does not shrink the datagram")
		packet.buffer.Release()
	}
	// A change to Handshake resets the temporary Initial estimate.
	handshake := tp.packer.getLongHeader(protocol.EncryptionHandshake, protocol.Version1)
	require.Equal(t, protocol.PacketNumberLen1, handshake.PacketNumberLen)
	// An old 0-RTT estimate cannot affect a 1-RTT short header, despite sharing
	// the Application Data packet-number space.
	ackhandler.SetCoalescedPacketSize(handler, protocol.PacketNumberSpaceAppData, 262)
	_, width := tp.packer.peekShortHeaderPacketNumber()
	require.Equal(t, protocol.PacketNumberLen1, width)

	// Long-header PTO probes must replace, rather than retain, a previous
	// datagram's temporary budget as normal coalesced sends do.
	var probeBudget protocol.ByteCount
	tp.packer.coalescedPacketSize = func(space protocol.PacketNumberSpace, size protocol.ByteCount) {
		probeBudget = size
		ackhandler.SetCoalescedPacketSize(handler, space, size)
	}
	probeFrame := &wire.CryptoFrame{Offset: 20, Data: []byte("probe")}
	tp.retransmissionQueue.addInitial(probeFrame)
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(ctrl), nil)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), false).Return(nil)
	probe, err := tp.packer.PackPTOProbePacket(protocol.EncryptionInitial, 1250, true, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	defer probe.buffer.Release()
	probeHeader := probe.longHdrPackets[0].header
	require.Equal(t, protocol.ByteCount(1250)-probeHeader.GetLength(protocol.Version1)-7-probeFrame.Length(protocol.Version1), probeBudget)
}

func TestCoalescedPacketBudgetRejectsUnusableRemainder(t *testing.T) {
	var recorded protocol.ByteCount
	var space protocol.PacketNumberSpace
	p := &packetPacker{coalescedPacketSize: func(s protocol.PacketNumberSpace, n protocol.ByteCount) { space, recorded = s, n }}
	header := &wire.ExtendedHeader{Header: wire.Header{Type: protocol.PacketTypeInitial, Version: protocol.Version1, DestConnectionID: protocol.ParseConnectionID([]byte("clientid"))}, PacketNumber: 1, PacketNumberLen: 1}
	const overhead = protocol.ByteCount(16)
	minimum := header.GetLength(protocol.Version1) + overhead + 3
	for _, size := range []protocol.ByteCount{-1, 0, 1, minimum - 1, minimum, minimum + 1, 262} {
		p.recordCoalescedPacketSize(header, overhead, size, protocol.Version1)
		want := size
		if size < minimum {
			want = 0
		}
		require.Equal(t, want, recorded)
		require.Equal(t, protocol.PacketNumberSpaceInitial, space)
	}
	p.recordCoalescedPacketSize(nil, 0, 262, protocol.Version1)
	require.Zero(t, recorded, "short-header packets end the long-header coalescing estimate")
	require.Equal(t, protocol.PacketNumberSpaceAppData, space)
}
