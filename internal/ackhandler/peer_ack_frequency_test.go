package ackhandler

import (
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/congestion"
	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestPeerAckFrequencyRearmsPTO(t *testing.T) {
	rtt := utils.NewRTTStats()
	rtt.UpdateRTT(20*time.Millisecond, 0)
	h := NewSentPacketHandler(0, 1200, rtt, new(utils.ConnectionStats), true, false, func(protocol.PacketNumber) {},
		protocol.PerspectiveClient, nil, utils.DefaultLogger).(*sentPacketHandler)
	h.handshakeConfirmed = true
	h.peerCompletedAddressValidation = true
	now := monotime.Now()
	h.SentPacket(now, 0, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}, Handler: &customFrameHandler{}}},
		protocol.Encryption1RTT, protocol.ECNNon, 100, false, false)
	before := h.GetLossDetectionTimeout()
	require.False(t, before.IsZero())
	h.SetPeerMaxAckDelay(50*time.Millisecond, now)
	require.Equal(t, 50*time.Millisecond, h.GetLossDetectionTimeout().Sub(before))
	h.SetPeerMaxAckDelay(time.Millisecond, now)
	require.Equal(t, time.Millisecond, h.GetLossDetectionTimeout().Sub(before))
	window, packet := h.AckFrequencyState()
	require.Positive(t, window)
	require.EqualValues(t, 1200, packet)
}

func TestInitialCongestionWindowAndMigration(t *testing.T) {
	for _, packets := range []uint32{0, 10} {
		rtt := utils.NewRTTStats()
		h := NewSentPacketHandler(0, 1200, rtt, new(utils.ConnectionStats), true, false, func(protocol.PacketNumber) {},
			protocol.PerspectiveClient, nil, utils.DefaultLogger, ClientSendConfig{Congestion: congestion.SenderConfig{InitialWindowPackets: packets}})
		want := packets
		if want == 0 {
			want = 32
		}
		window, mtu := h.AckFrequencyState()
		require.EqualValues(t, want*1200, window)
		require.EqualValues(t, 1200, mtu)
		h.MigratedPath(monotime.Now(), 1280)
		window, mtu = h.AckFrequencyState()
		require.EqualValues(t, want*1280, window)
		require.EqualValues(t, 1280, mtu)
	}
}

func TestCongestionPolicySurvivesPathMigration(t *testing.T) {
	for _, config := range []congestion.SenderConfig{
		{Algorithm: congestion.AlgorithmCubic, SlowStart: congestion.SlowStartClassic, InitialWindowPackets: 10},
		{Algorithm: congestion.AlgorithmCubicBytes, SlowStart: congestion.SlowStartHybrid, InitialWindowPackets: 32, SegmentSize: 1460, Connections: 2},
	} {
		h := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), new(utils.ConnectionStats), true, false, func(protocol.PacketNumber) {}, protocol.PerspectiveClient, nil, utils.DefaultLogger, ClientSendConfig{Congestion: config}).(*sentPacketHandler)
		h.MigratedPath(monotime.Now(), 1280)
		require.Equal(t, config, h.congestionConfig)
		window, _ := h.AckFrequencyState()
		segment := uint64(1280)
		if config.SegmentSize != 0 {
			segment = uint64(config.SegmentSize)
		}
		require.EqualValues(t, uint64(config.InitialWindowPackets)*segment, window)
		// Server constructors never apply client-only congestion policies.
		server := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), new(utils.ConnectionStats), true, false, func(protocol.PacketNumber) {}, protocol.PerspectiveServer, nil, utils.DefaultLogger, ClientSendConfig{Congestion: config}).(*sentPacketHandler)
		require.Zero(t, server.congestionConfig)
		server.MigratedPath(monotime.Now(), 1280)
		window, _ = server.AckFrequencyState()
		require.EqualValues(t, 32*1280, window)
	}
}
