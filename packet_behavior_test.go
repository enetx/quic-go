package quic

import (
	"fmt"
	"testing"

	"github.com/enetx/quic-go/internal/handshake"
	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestPacketPackerAckOnlyPingPolicy(t *testing.T) {
	for _, threshold := range []int{-1, 0, 2} {
		t.Run(fmt.Sprint(threshold), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
			tp.packer.ackOnlyPingThreshold = threshold
			for i := 1; i <= 45; i++ {
				tp.pnManager.EXPECT().PeekPacketNumber(protocol.PacketNumberSpaceAppData).Return(protocol.PacketNumber(i), protocol.PacketNumberLen2)
				tp.pnManager.EXPECT().PopPacketNumber(protocol.PacketNumberSpaceAppData).Return(protocol.PacketNumber(i))
				tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(ctrl), nil)
				tp.framer.EXPECT().HasData().Return(true)
				tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false).Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
				expectAppendFrames(tp.framer, nil, nil)
				buffer := getPacketBuffer()
				packet, err := tp.packer.AppendPacket(buffer, 1200, monotime.Now(), protocol.Version1)
				require.NoError(t, err)
				period := threshold + 1
				if threshold == 0 {
					period = 20
				}
				if threshold >= 0 && i%period == 0 {
					require.Len(t, packet.Frames, 1)
					require.IsType(t, &wire.PingFrame{}, packet.Frames[0].Frame)
				} else {
					require.Empty(t, packet.Frames)
				}
				buffer.Release()
			}
		})
	}
}

func TestOmitInitialAckWhenHandshakeDataReady(t *testing.T) {
	for _, omit := range []bool{false, true} {
		t.Run(fmt.Sprint(omit), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
			tp.packer.omitInitialAckOnHandshake = omit
			tp.handshakeStream.Write(make([]byte, 50))
			tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(ctrl), nil)
			times := 1
			if omit {
				times = 2
			}
			tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(ctrl), nil).Times(times)
			tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
			tp.sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
			if !omit {
				tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), true).Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}})
				tp.pnManager.EXPECT().PeekPacketNumber(protocol.PacketNumberSpaceInitial).Return(protocol.PacketNumber(0), protocol.PacketNumberLen1)
				tp.pnManager.EXPECT().PopPacketNumber(protocol.PacketNumberSpaceInitial).Return(protocol.PacketNumber(0))
			}
			tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, gomock.Any(), false)
			tp.pnManager.EXPECT().PeekPacketNumber(protocol.PacketNumberSpaceHandshake).Return(protocol.PacketNumber(0), protocol.PacketNumberLen1)
			tp.pnManager.EXPECT().PopPacketNumber(protocol.PacketNumberSpaceHandshake).Return(protocol.PacketNumber(0))
			packet, err := tp.packer.PackCoalescedPacket(false, 1250, monotime.Now(), protocol.Version1)
			require.NoError(t, err)
			defer packet.buffer.Release()
			count := 2
			if omit {
				count = 1
			}
			require.Len(t, packet.longHdrPackets, count)
			require.Equal(t, protocol.EncryptionHandshake, packet.longHdrPackets[count-1].EncryptionLevel())
			if omit {
				require.Less(t, packet.buffer.Len(), protocol.ByteCount(1200))
			}
		})
	}
}

func TestPacketPackerTimedAckProbe(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		t.Run(fmt.Sprint(allowed), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
			now := monotime.Now()
			calls := 0
			tp.packer.shouldProbeAckOnly = func(at monotime.Time) bool { require.Equal(t, now, at); calls++; return true }
			tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true).Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
			if allowed {
				tp.framer.EXPECT().HasData().Return(false)
			}
			pl := tp.packer.maybeGetAppDataPacket(1200, !allowed, true, now, protocol.Version1)
			if allowed {
				require.Equal(t, 1, calls)
				require.Len(t, pl.frames, 1)
				require.IsType(t, &wire.PingFrame{}, pl.frames[0].Frame)
			} else {
				require.Zero(t, calls)
				require.Empty(t, pl.frames)
			}
		})
	}
}

func TestConnectionIDRotationCanBeDeferred(t *testing.T) {
	var retired []uint64
	m := newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4}), func(protocol.StatelessResetToken) {}, func(protocol.StatelessResetToken) {}, func(f wire.Frame) { retired = append(retired, f.(*wire.RetireConnectionIDFrame).SequenceNumber) })
	m.disableRotation = true
	m.SetHandshakeComplete()
	next := protocol.ParseConnectionID([]byte{5, 6, 7, 8})
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: next}))
	m.packetsSinceLastChange = m.packetsPerConnectionID + 1
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4}), m.Get())
	require.Empty(t, retired)
	// Peer retirement is mandatory even with unsolicited rotation disabled.
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{SequenceNumber: 1, RetirePriorTo: 1, ConnectionID: next}))
	require.Equal(t, next, m.Get())
	require.Equal(t, []uint64{0}, retired)
	// A distinct path can still reserve a replacement.
	third := protocol.ParseConnectionID([]byte{9, 10, 11, 12})
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{SequenceNumber: 2, ConnectionID: third}))
	id, ok := m.GetConnIDForPath(pathID(1))
	require.True(t, ok)
	require.Equal(t, third, id)
}
