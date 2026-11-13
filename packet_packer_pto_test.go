package quic

import (
	"testing"

	"github.com/enetx/quic-go/internal/ackhandler"
	"github.com/enetx/quic-go/internal/handshake"
	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func coalescedProbePacker(t *testing.T, early bool, acks bool) *testPacketPacker {
	t.Helper()
	ctrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
	tp.packer.initialPaddingMode = InitialPaddingDatagram
	tp.initialStream.scramble = false
	sealer := newMockShortHeaderSealer(ctrl)
	tp.sealingManager.EXPECT().GetInitialSealer().Return(sealer, nil).AnyTimes()
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(sealer, nil).AnyTimes()
	if early {
		tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable).AnyTimes()
		tp.sealingManager.EXPECT().Get0RTTSealer().Return(sealer, nil).AnyTimes()
	} else {
		tp.sealingManager.EXPECT().Get1RTTSealer().Return(sealer, nil).AnyTimes()
	}
	tp.framer.EXPECT().HasData().Return(false).AnyTimes()
	tp.ackFramer.EXPECT().GetAckFrame(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(protocol.EncryptionLevel, monotime.Time, bool) *wire.AckFrame {
		if acks {
			return &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}}
		}
		return nil
	}).AnyTimes()
	var numbers [3]protocol.PacketNumber
	tp.pnManager.EXPECT().PeekPacketNumber(gomock.Any()).DoAndReturn(func(space protocol.PacketNumberSpace) (protocol.PacketNumber, protocol.PacketNumberLen) {
		return numbers[space], protocol.PacketNumberLen1
	}).AnyTimes()
	tp.pnManager.EXPECT().PopPacketNumber(gomock.Any()).DoAndReturn(func(space protocol.PacketNumberSpace) protocol.PacketNumber {
		n := numbers[space]
		numbers[space]++
		return n
	}).AnyTimes()
	return tp
}

func TestPTOBatchPackerCoalescesForcedSpacesAndSuppressesCryptoFollowups(t *testing.T) {
	for _, version := range []protocol.Version{protocol.Version1, protocol.Version2} {
		for _, acks := range []bool{false, true} {
			tp := coalescedProbePacker(t, false, acks)
			packet, err := tp.packer.packPTOProbeDatagram([3]bool{true, true, true}, 1280, monotime.Now(), version)
			require.NoError(t, err)
			require.NotNil(t, packet)
			require.Len(t, packet.longHdrPackets, 2)
			require.NotNil(t, packet.shortHdrPacket)
			require.True(t, packet.longHdrPackets[0].IsAckEliciting())
			require.True(t, packet.longHdrPackets[1].IsAckEliciting())
			require.True(t, packet.shortHdrPacket.IsAckEliciting())
			require.EqualValues(t, 1280, packet.buffer.Len())
			require.Nil(t, tp.packer.ptoProbeForce)
			packet.buffer.Release()
			packet, err = tp.packer.packPTOProbeDatagram([3]bool{false, false, true}, 1280, monotime.Now(), version)
			require.NoError(t, err)
			require.NotNil(t, packet)
			for _, p := range packet.longHdrPackets {
				require.False(t, p.IsAckEliciting())
			}
			require.True(t, packet.shortHdrPacket.IsAckEliciting())
			packet.buffer.Release()
		}
	}
}

func TestPTOBatchPackerCoalescesEarlyApplicationData(t *testing.T) {
	tp := coalescedProbePacker(t, true, false)
	packet, err := tp.packer.packPTOProbeDatagram([3]bool{true, false, true}, 1280, monotime.Now(), protocol.Version2)
	require.NoError(t, err)
	require.NotNil(t, packet)
	require.Len(t, packet.longHdrPackets, 2)
	require.Equal(t, protocol.EncryptionInitial, packet.longHdrPackets[0].EncryptionLevel())
	require.Equal(t, protocol.Encryption0RTT, packet.longHdrPackets[1].EncryptionLevel())
	require.True(t, packet.longHdrPackets[1].IsAckEliciting())
	packet.buffer.Release()
}

func TestPTOBatchPackerKeepsRemainingInitialCryptoAheadOfLaterSpaces(t *testing.T) {
	tp := coalescedProbePacker(t, true, false)
	hello, err := getClientHello("example.com")
	require.NoError(t, err)
	tp.initialStream.layout = func(info InitialCryptoLayoutInfo) [][]CryptoRange {
		return [][]CryptoRange{{{Offset: 0, Length: 1}}, {{Offset: 1, Length: info.Length - 1}}}
	}
	_, err = tp.initialStream.Write(hello)
	require.NoError(t, err)
	packet, err := tp.packer.packPTOProbeDatagram([3]bool{true, true, true}, 1280, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, packet)
	require.Len(t, packet.longHdrPackets, 1)
	require.Equal(t, protocol.EncryptionInitial, packet.longHdrPackets[0].EncryptionLevel())
	require.True(t, tp.initialStream.HasData())
	require.Nil(t, packet.shortHdrPacket)
	packet.buffer.Release()
}

func TestPTOBatchForcedACKPayloadFitsBudget(t *testing.T) {
	p := &packetPacker{ptoProbeForce: &[3]bool{true, true, true}}
	ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 110, Largest: 120}, {Smallest: 0, Largest: 100}}}
	budget := ack.Length(protocol.Version1)
	pl := p.forcePTOProbe(payload{ack: ack, length: budget}, protocol.PacketNumberSpaceInitial, budget, protocol.Version1)
	require.True(t, ackhandler.HasAckElicitingFrames(pl.frames))
	require.LessOrEqual(t, pl.length, budget)
	require.EqualValues(t, 0, p.numNonAckElicitingAcks)
}
