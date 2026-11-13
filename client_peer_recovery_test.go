package quic

import (
	"testing"

	"github.com/enetx/quic-go/internal/handshake"
	"github.com/enetx/quic-go/internal/mocks"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/enetx/quic-go/qlog"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestPeerMissingKeysNeverBypassesAuthentication(t *testing.T) {
	var calls int
	r := &cryptoRangeRecovery{data: []byte("hello"), sent: []CryptoRange{{Length: 5}}}
	c := &Conn{perspective: protocol.PerspectiveClient, config: &Config{ClientHandshake: &ClientHandshake{PeerPacketRecoveryPolicy: func(info PeerPacketInfo) PeerPacketRecovery {
		calls++
		return PeerPacketRecovery{ResendInitialCrypto: true}
	}}}, initialStream: &initialCryptoStream{recovery: r}}
	c.recoverFromUnpackError(handshake.ErrDecryptionFailed, qlog.PacketTypeHandshake)
	require.Zero(t, calls)
	require.Empty(t, r.pending)
	c.recoverFromUnpackError(handshake.ErrKeysNotYetAvailable, qlog.PacketTypeHandshake)
	require.Equal(t, 1, calls)
	require.Equal(t, r.sent, r.pending)
	r.pending = nil
	c.handshakeComplete = true
	c.recoverFromUnpackError(handshake.ErrKeysNotYetAvailable, qlog.PacketTypeHandshake)
	require.Empty(t, r.pending)
	c.handshakeComplete = false
	r.close()
	c.recoverFromUnpackError(handshake.ErrKeysNotYetAvailable, qlog.PacketTypeHandshake)
	require.Empty(t, r.pending)
	c.perspective = protocol.PerspectiveServer
	calls = 0
	c.recoverFromUnpackError(handshake.ErrKeysNotYetAvailable, qlog.PacketTypeHandshake)
	require.Zero(t, calls)
}

func TestPeerDroppedInitialOnlyProbesAvailableHandshakeKeys(t *testing.T) {
	setup := mocks.NewMockCryptoSetup(gomock.NewController(t))
	sealer, _ := handshake.NewInitialAEAD(protocol.ConnectionID{}, protocol.PerspectiveClient, protocol.Version1)
	c := &Conn{perspective: protocol.PerspectiveClient, config: &Config{ClientHandshake: &ClientHandshake{PeerPacketRecoveryPolicy: func(PeerPacketInfo) PeerPacketRecovery { return PeerPacketRecovery{ProbeHandshake: true} }}}, packer: &packetPacker{cryptoSetup: setup}, retransmissionQueue: newRetransmissionQueue()}
	setup.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysDropped)
	c.recoverFromUnpackError(handshake.ErrKeysDropped, qlog.PacketTypeInitial)
	require.False(t, c.retransmissionQueue.HasData(protocol.EncryptionHandshake))
	setup.EXPECT().GetHandshakeSealer().Return(sealer, nil)
	c.recoverFromUnpackError(handshake.ErrKeysDropped, qlog.PacketTypeInitial)
	require.True(t, c.retransmissionQueue.HasData(protocol.EncryptionHandshake))
	c.recoverFromUnpackError(handshake.ErrKeysDropped, qlog.PacketTypeInitial)
	require.Len(t, c.retransmissionQueue.handshake.other, 1, "coalesce simultaneous hints")
}

func TestHandshakeCryptoRangeRecoveryRetiresPendingCopy(t *testing.T) {
	s := newCryptoStream()
	s.recovery = &cryptoRangeRecovery{peerProbe: true}
	_, err := s.Write([]byte("client Finished"))
	require.NoError(t, err)
	frame := s.PopCryptoFrame(1200)
	s.recovery.sent = []CryptoRange{{Length: len(frame.Data)}}
	q := newRetransmissionQueue()
	q.handshakeRecovery = s.recovery
	q.addHandshake(frame)
	require.True(t, q.HasData(protocol.EncryptionHandshake))
	require.NoError(t, s.recovery.prepare(1200, 1150))
	require.Equal(t, frame, q.GetFrame(protocol.EncryptionHandshake, 1150, protocol.Version1))
	s.recovery.resendUnacked()
	require.True(t, q.HasData(protocol.EncryptionHandshake))
	q.AckHandler(protocol.EncryptionHandshake).OnAcked(frame)
	require.False(t, q.HasData(protocol.EncryptionHandshake))
	q.DropPackets(protocol.EncryptionHandshake)
	require.Nil(t, s.recovery.data)
	q.AckHandler(protocol.EncryptionHandshake).OnLost(&wire.CryptoFrame{Data: []byte("late")})
	require.Empty(t, s.recovery.pending)
}

func TestApplicationProbeNumberPolicyClone(t *testing.T) {
	value := true
	h := &ClientHandshake{ApplicationProbeSkipPacketNumber: &value}
	clone := h.Clone()
	value = false
	require.True(t, *clone.ApplicationProbeSkipPacketNumber)
	*clone.ApplicationProbeSkipPacketNumber = false
	value = true
	require.True(t, *h.ApplicationProbeSkipPacketNumber)
	require.False(t, *clone.ApplicationProbeSkipPacketNumber)
	require.Nil(t, (&ClientHandshake{}).Clone().ApplicationProbeSkipPacketNumber)
}
