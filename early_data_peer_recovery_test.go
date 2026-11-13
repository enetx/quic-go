package quic

import (
	"testing"

	"github.com/enetx/quic-go/internal/ackhandler"
	"github.com/enetx/quic-go/internal/handshake"
	"github.com/enetx/quic-go/internal/mocks"
	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/enetx/quic-go/qlog"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type peerEarlyFrameHandler struct{ lost int }

func (h *peerEarlyFrameHandler) OnAcked(wire.Frame) {}
func (h *peerEarlyFrameHandler) OnLost(wire.Frame)  { h.lost++ }

func TestEarlyDataPeerHintBoundaries(t *testing.T) {
	for _, scenario := range []string{"missing-handshake", "missing-application", "bad-mac", "retired-keys", "complete", "rejected", "server", "nil-policy", "nonprogress-initial", "progress-initial", "nonprogress-handshake", "crypto-opt-out", "ping"} {
		t.Run(scenario, func(t *testing.T) {
			h := ackhandler.NewSentPacketHandler(0, 1252, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger)
			r := &peerEarlyFrameHandler{}
			h.SentPacket(monotime.Now(), h.PopPacketNumber(protocol.PacketNumberSpaceAppData), protocol.InvalidPacketNumber, []ackhandler.StreamFrame{{Frame: &wire.StreamFrame{Data: []byte("early")}, Handler: r}}, nil, protocol.Encryption0RTT, protocol.ECNNon, 100, false, false)
			policy := &ClientHandshake{EarlyDataResendOnPeerCrypto: true, PeerPacketRecoveryPolicy: func(PeerPacketInfo) PeerPacketRecovery { return PeerPacketRecovery{ResendEarlyData: true} }}
			initial, hs := newInitialCryptoStream(true), newCryptoStream()
			c := &Conn{perspective: protocol.PerspectiveClient, config: &Config{ClientHandshake: policy}, sentPacketHandler: h, initialStream: initial, handshakeStream: hs, logger: utils.DefaultLogger, cryptoStreamManager: newCryptoStreamManager(initial, hs, newCryptoStream())}
			cs := mocks.NewMockCryptoSetup(gomock.NewController(t))
			cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}).AnyTimes()
			c.cryptoStreamHandler = cs
			want := 0
			switch scenario {
			case "nonprogress-initial", "nonprogress-handshake", "crypto-opt-out", "progress-initial":
				level, offset := protocol.EncryptionInitial, protocol.ByteCount(100)
				if scenario == "nonprogress-handshake" {
					level = protocol.EncryptionHandshake
				}
				if scenario == "crypto-opt-out" {
					policy.EarlyDataResendOnPeerCrypto = false
				}
				if scenario == "progress-initial" {
					offset = 0
					cs.EXPECT().HandleMessage([]byte{1}, level).Return(nil)
				}
				require.NoError(t, c.handleCryptoFrame(&wire.CryptoFrame{Offset: offset, Data: []byte{1}}, level, monotime.Now()))
				if scenario == "nonprogress-initial" {
					want = 1
				}
			case "ping":
				_, err := c.handleFrame(&wire.PingFrame{}, protocol.EncryptionInitial, protocol.ConnectionID{}, monotime.Now())
				require.NoError(t, err)
			default:
				pt, err := qlog.PacketTypeHandshake, handshake.ErrKeysNotYetAvailable
				switch scenario {
				case "missing-application":
					pt = qlog.PacketType1RTT
				case "bad-mac":
					err = handshake.ErrDecryptionFailed
				case "retired-keys":
					err = handshake.ErrKeysDropped
				case "complete":
					c.handshakeComplete = true
				case "rejected":
					c.earlyDataRejected = true
				case "server":
					c.perspective = protocol.PerspectiveServer
				case "nil-policy":
					policy.PeerPacketRecoveryPolicy = nil
				}
				c.recoverFromUnpackError(err, pt)
				if scenario == "missing-handshake" || scenario == "missing-application" {
					want = 1
				}
			}
			require.Equal(t, want, r.lost)
		})
	}
}
