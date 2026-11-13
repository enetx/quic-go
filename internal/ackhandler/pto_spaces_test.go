package ackhandler

import (
	"fmt"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestPTOSpaceAllowanceAndNumberGap(t *testing.T) {
	for _, level := range []protocol.EncryptionLevel{protocol.EncryptionHandshake, protocol.Encryption1RTT} {
		for _, count := range []uint8{0, 1, 2} {
			for _, skip := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/count=%d/skip=%t", level, count, skip), func(t *testing.T) {
					opts := ClientSendConfig{HandshakeProbePackets: count, ApplicationProbePackets: count, HandshakeProbeSkipPacketNumber: skip, DisablePacketNumberSkipping: true, ApplicationProbeSkipPacketNumber: &skip, RetainHandshakeCryptoProbes: true, SeparatePacketNumberSpaces: true}
					h := NewSentPacketHandler(0, 1252, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger, opts).(*sentPacketHandler)
					now := monotime.Now()
					h.DropPackets(protocol.EncryptionInitial, now)
					if level == protocol.Encryption1RTT {
						h.DropPackets(protocol.EncryptionHandshake, now)
					}
					space := level.PacketNumberSpace()
					pn := h.PopPacketNumber(space)
					var acked int
					h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.CryptoFrame{Data: []byte("transcript")}, Handler: &customFrameHandler{onLost: func(wire.Frame) {}, onAcked: func(wire.Frame) { acked++ }}}}, level, protocol.ECNNon, 1252, false, false)
					deadline := h.GetLossDetectionTimeout()
					require.False(t, deadline.IsZero())
					require.NoError(t, h.OnLossDetectionTimeout(deadline))
					want := int(count)
					if want == 0 {
						want = 2
					}
					require.Equal(t, want, h.numProbesToSend)
					next := h.PopPacketNumber(space)
					if skip {
						require.Equal(t, pn+2, next)
					} else {
						require.Equal(t, pn+1, next)
					}
					if level == protocol.EncryptionHandshake {
						require.True(t, h.QueueProbePacket(space))
						_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, level, deadline.Add(time.Millisecond))
						require.NoError(t, err)
						require.Equal(t, 1, acked)
					}
				})
			}
		}
	}
}

func TestHandshakeProbeEmptyFollowupAndValidationOnly(t *testing.T) {
	h := NewSentPacketHandler(0, 1252, utils.NewRTTStats(), &utils.ConnectionStats{}, false, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger, ClientSendConfig{HandshakeProbePackets: 2, HandshakeProbeSkipPacketNumber: true}).(*sentPacketHandler)
	h.DropPackets(protocol.EncryptionInitial, monotime.Now())
	require.NoError(t, h.OnLossDetectionTimeout(monotime.Now()))
	require.Equal(t, SendPTOHandshake, h.ptoMode)
	require.Equal(t, 2, h.numProbesToSend)
	require.EqualValues(t, 1, h.PopPacketNumber(protocol.PacketNumberSpaceHandshake))
	require.False(t, SkipEmptyHandshakeProbe(h), "the first probe cannot be suppressed")
	h.numProbesToSend--
	require.True(t, SkipEmptyHandshakeProbe(h))
	require.Zero(t, h.numProbesToSend)
	require.False(t, SkipEmptyHandshakeProbe(h))
}

func TestImmediatePingACKSurvivesReceivePolicies(t *testing.T) {
	for _, mode := range []string{"native", "policy", "legacy"} {
		h := NewReceivedPacketHandler(utils.DefaultLogger)
		if mode == "policy" {
			h.appDataPackets.ackPolicy = &AckPolicy{PacketThreshold: 10}
		}
		if mode == "legacy" {
			h.SetLegacyAckFrequency(time.Microsecond)
			require.NoError(t, h.HandleLegacyAckFrequency(&wire.LegacyAckFrequencyFrame{AckElicitingThreshold: 10, RequestMaxAckDelay: time.Second}))
		}
		now := monotime.Now()
		require.NoError(t, h.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true))
		h.GetAckFrame(protocol.Encryption1RTT, now, false)
		h.QueueImmediateACK()
		require.NoError(t, h.ReceivedPacket(1, protocol.ECNNon, protocol.Encryption1RTT, now.Add(time.Millisecond), true))
		ack := h.GetAckFrame(protocol.Encryption1RTT, now.Add(time.Millisecond), true)
		require.NotNil(t, ack)
		require.EqualValues(t, 1, ack.LargestAcked())
	}
}

func TestApplicationPTOSkipWithoutRandomGaps(t *testing.T) {
	skip := true
	h := NewSentPacketHandler(0, 1252, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger, ClientSendConfig{DisablePacketNumberSkipping: true, ApplicationProbeSkipPacketNumber: &skip, ApplicationProbePackets: 1}).(*sentPacketHandler)
	now := monotime.Now()
	h.DropPackets(protocol.EncryptionInitial, now)
	h.DropPackets(protocol.EncryptionHandshake, now)
	for number := range 1000 {
		require.EqualValues(t, number, h.PopPacketNumber(protocol.PacketNumberSpaceAppData))
	}
	pn := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
	h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}, Handler: &customFrameHandler{onLost: func(wire.Frame) {}}}}, protocol.Encryption1RTT, protocol.ECNNon, 100, false, false)
	deadline := h.GetLossDetectionTimeout()
	require.NoError(t, h.OnLossDetectionTimeout(deadline))
	probe := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
	require.Equal(t, pn+2, probe)
	h.SentPacket(deadline.Add(time.Millisecond), probe, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}, Handler: &customFrameHandler{onLost: func(wire.Frame) {}}}}, protocol.Encryption1RTT, protocol.ECNNon, 100, false, false)
	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn + 1)}, protocol.Encryption1RTT, now.Add(time.Second))
	require.Error(t, err, "a skipped-number ACK must remain invalid")
}

func TestCryptoProbesDoNotBorrowFramesFromOtherSpaces(t *testing.T) {
	h := NewSentPacketHandler(0, 1252, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger, ClientSendConfig{RetainInitialCryptoProbes: true, RetainHandshakeCryptoProbes: true}).(*sentPacketHandler)
	called := make(map[protocol.EncryptionLevel]int)
	for _, level := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.Encryption1RTT, protocol.EncryptionHandshake} {
		pn := h.PopPacketNumber(level.PacketNumberSpace())
		h.SentPacket(monotime.Now(), pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.CryptoFrame{Data: []byte("epoch")}, Handler: &customFrameHandler{onLost: func(wire.Frame) { called[level]++ }}}}, level, protocol.ECNNon, 100, false, false)
	}
	require.True(t, h.QueueProbePacket(protocol.PacketNumberSpaceHandshake))
	require.Equal(t, map[protocol.EncryptionLevel]int{protocol.EncryptionHandshake: 1}, called)
	require.False(t, h.QueueProbePacket(protocol.PacketNumberSpaceHandshake), "shared numbering must not share CRYPTO epochs")
	require.True(t, h.QueueProbePacket(protocol.PacketNumberSpaceInitial))
	require.Equal(t, map[protocol.EncryptionLevel]int{protocol.EncryptionHandshake: 1, protocol.EncryptionInitial: 1}, called)
}
