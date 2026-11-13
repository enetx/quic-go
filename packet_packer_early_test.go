package quic

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/enetx/quic-go/internal/ackhandler"
	"github.com/enetx/quic-go/internal/handshake"
	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestSmallEarlyPacketProtectionAndNativeThreshold(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for pn := protocol.PacketNumberLen1; pn <= protocol.PacketNumberLen4; pn++ {
			// Header fields before PN occupy 21 bytes for the test connection IDs.
			minimum := protocol.ByteCount(21+int(pn)+7) + max(1, 4-protocol.ByteCount(pn))
			for _, budget := range []protocol.ByteCount{minimum - 1, minimum, 64, 127} {
				t.Run(fmt.Sprintf("enabled=%v/pn=%d/budget=%d", enabled, pn, budget), func(t *testing.T) {
					ctrl := gomock.NewController(t)
					tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
					tp.packer.coalesceSmallEarlyPackets = enabled
					tp.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
					if enabled {
						tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
						tp.sealingManager.EXPECT().Get0RTTSealer().Return(newMockShortHeaderSealer(ctrl), nil)
						tp.pnManager.EXPECT().PeekPacketNumber(protocol.PacketNumberSpaceAppData).Return(protocol.PacketNumber(17), pn)
						if budget >= minimum {
							tp.framer.EXPECT().HasData().Return(true)
							expectAppendFrames(tp.framer, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, nil)
							tp.pnManager.EXPECT().PopPacketNumber(protocol.PacketNumberSpaceAppData).Return(protocol.PacketNumber(17))
						}
					}
					packet, err := tp.packer.PackCoalescedPacket(false, budget, monotime.Now(), protocol.Version1)
					require.NoError(t, err)
					if !enabled || budget < minimum {
						require.Nil(t, packet)
						return
					}
					require.NotNil(t, packet)
					require.LessOrEqual(t, packet.buffer.Len(), budget)
					hdrs, rest := parsePacket(t, packet.buffer.Data)
					require.Len(t, hdrs, 1)
					require.Empty(t, rest)
					require.Equal(t, protocol.PacketType0RTT, hdrs[0].Type)
				})
			}
		}
	}
}

func TestSmallEarlyStreamUsesTailBehindInitial(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%v", enabled), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			tc := newClientTestConnection(t, ctrl, nil, true)
			tc.conn.restoreTransportParameters(&wire.TransportParameters{ActiveConnectionIDLimit: 2, InitialMaxData: 4096, InitialMaxStreamDataUni: 1024, MaxUniStreamNum: 3})
			stream, err := tc.conn.OpenUniStream()
			require.NoError(t, err)
			require.NoError(t, stream.TryWriteAll(bytes.Repeat([]byte("control"), 30)))
			tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
			tp.packer.coalesceSmallEarlyPackets = enabled
			tp.packer.framer = tc.conn.framer
			tp.initialStream.scramble = false
			_, err = tp.initialStream.Write(make([]byte, 1080))
			require.NoError(t, err)
			tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(ctrl), nil)
			tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), false).Return(nil)
			tp.pnManager.EXPECT().PeekPacketNumber(protocol.PacketNumberSpaceInitial).Return(protocol.PacketNumber(1), protocol.PacketNumberLen1)
			tp.pnManager.EXPECT().PopPacketNumber(protocol.PacketNumberSpaceInitial).Return(protocol.PacketNumber(1))
			if enabled {
				tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				tp.sealingManager.EXPECT().Get0RTTSealer().Return(newMockShortHeaderSealer(ctrl), nil)
				tp.pnManager.EXPECT().PeekPacketNumber(protocol.PacketNumberSpaceAppData).Return(protocol.PacketNumber(0), protocol.PacketNumberLen1)
				tp.pnManager.EXPECT().PopPacketNumber(protocol.PacketNumberSpaceAppData).Return(protocol.PacketNumber(0))
			}
			packet, err := tp.packer.PackCoalescedPacket(false, 1200, monotime.Now(), protocol.Version1)
			require.NoError(t, err)
			require.NotNil(t, packet)
			require.Equal(t, protocol.ByteCount(1200), packet.buffer.Len())
			want := 1
			if enabled {
				want = 2
			}
			require.Len(t, packet.longHdrPackets, want)
			if enabled {
				early := packet.longHdrPackets[1]
				require.Equal(t, protocol.PacketType0RTT, early.header.Type)
				require.Less(t, uint64(early.length), uint64(protocol.MinCoalescedPacketSize))
				require.NotEmpty(t, early.streamFrames, "the stream framer retained its native 128-byte threshold")
				require.Equal(t, stream.StreamID(), early.streamFrames[0].Frame.StreamID)
			}
			hdrs, rest := parsePacket(t, packet.buffer.Data)
			require.Len(t, hdrs, want)
			require.Empty(t, rest)
		})
	}
}

func TestSmallEarlyPacketPolicyDoesNotMakeACKOr1RTTTailsEligible(t *testing.T) {
	for _, onlyACK := range []bool{false, true} {
		t.Run(fmt.Sprintf("ack-only=%v", onlyACK), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
			tp.packer.coalesceSmallEarlyPackets = true
			tp.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
			if onlyACK {
				tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
			} else {
				tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(ctrl), nil)
			}
			packet, err := tp.packer.PackCoalescedPacket(onlyACK, 64, monotime.Now(), protocol.Version1)
			require.NoError(t, err)
			require.Nil(t, packet)
		})
	}
}

func TestSmallEarlyPacketKeepsTheTicketVersion(t *testing.T) {
	for _, version := range []protocol.Version{protocol.Version1, protocol.Version2} {
		for _, ticketVersion := range []protocol.Version{0, protocol.Version1, protocol.Version2} {
			t.Run(fmt.Sprintf("initial=%x/ticket=%x", version, ticketVersion), func(t *testing.T) {
				ctrl := gomock.NewController(t)
				tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
				tp.packer.coalesceSmallEarlyPackets = true
				tp.packer.zeroRTTVersion = ticketVersion
				tp.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
				tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				tp.sealingManager.EXPECT().Get0RTTSealer().Return(newMockShortHeaderSealer(ctrl), nil)
				tp.pnManager.EXPECT().PeekPacketNumber(protocol.PacketNumberSpaceAppData).Return(protocol.PacketNumber(0), protocol.PacketNumberLen1)
				tp.pnManager.EXPECT().PopPacketNumber(protocol.PacketNumberSpaceAppData).Return(protocol.PacketNumber(0))
				tp.framer.EXPECT().HasData().Return(true)
				expectAppendFrames(tp.framer, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, nil)
				packet, err := tp.packer.PackCoalescedPacket(false, 64, monotime.Now(), version)
				require.NoError(t, err)
				hdrs, rest := parsePacket(t, packet.buffer.Data)
				require.Len(t, hdrs, 1)
				require.Empty(t, rest)
				want := version
				if ticketVersion != 0 {
					want = ticketVersion
				}
				require.Equal(t, want, hdrs[0].Version)
				require.Equal(t, protocol.PacketType0RTT, hdrs[0].Type)
			})
		}
	}
}

func TestSmallEarlyTailKeepsDatagramForTheNextFullPacket(t *testing.T) {
	ctrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
	tp.packer.coalesceSmallEarlyPackets = true
	data := bytes.Repeat([]byte("D"), 200)
	require.NoError(t, tp.datagramQueue.Add(&wire.DatagramFrame{Data: data, DataLenPresent: true}))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped).Times(2)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable).Times(2)
	tp.sealingManager.EXPECT().Get0RTTSealer().Return(newMockShortHeaderSealer(ctrl), nil).Times(2)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PacketNumberSpaceAppData).Return(protocol.PacketNumber(17), protocol.PacketNumberLen1).Times(2)
	tp.framer.EXPECT().HasData().Return(false).Times(2)
	small, err := tp.packer.PackCoalescedPacket(false, 64, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Nil(t, small)
	require.NotNil(t, tp.datagramQueue.Peek(), "a temporary tail consumed the queued message")
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PacketNumberSpaceAppData).Return(protocol.PacketNumber(17))
	full, err := tp.packer.PackCoalescedPacket(false, 1024, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, full)
	require.Len(t, full.longHdrPackets, 1)
	require.Len(t, full.longHdrPackets[0].frames, 1)
	require.Equal(t, data, full.longHdrPackets[0].frames[0].Frame.(*wire.DatagramFrame).Data)
	require.Nil(t, tp.datagramQueue.Peek())
}
