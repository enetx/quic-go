package quic

import (
	"fmt"
	"testing"

	"github.com/enetx/quic-go/internal/ackhandler"
	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// A full receive queue must not turn an explicit ACK threshold into a threshold
// plus the remainder of a 32-packet event-loop batch.
func TestConnectionReceiveQueueACKFlush(t *testing.T) {
	for _, threshold := range []uint64{2, 10} {
		for _, flush := range []bool{false, true} {
			t.Run(fmt.Sprintf("threshold=%d/flush=%v", threshold, flush), func(t *testing.T) {
				ctrl := gomock.NewController(t)
				unpacker := NewMockUnpacker(ctrl)
				tc := newServerTestConnection(t, ctrl, nil, false,
					connectionOptUnpacker(unpacker), connectionOptHandshakeConfirmed())
				defer tc.conn.receivedPackets.Clear()
				tc.receivedPacketHandler().SetAckPolicy(&ackhandler.AckPolicy{
					PacketThreshold: threshold, FlushOnPacket: flush,
				}, nil)

				var pn protocol.PacketNumber
				unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ monotime.Time, _ []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error) {
						pn++
						return pn, protocol.PacketNumberLen2, 0, []byte{0x1}, nil // authenticated PING
					},
				).AnyTimes()
				for range 96 {
					packet := getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, 1, []byte("encrypted"))
					packet.rcvTime = monotime.Now()
					tc.conn.handlePacket(packet)
				}

				for range 2 {
					before := pn
					processed, err := tc.conn.handlePackets()
					require.NoError(t, err)
					require.True(t, processed)
					want := uint64(maxPacketsToProcess)
					if flush {
						want = threshold
					}
					require.EqualValues(t, want, pn-before)
					require.False(t, tc.conn.receivedPackets.Empty())
					select {
					case <-tc.conn.notifyReceivedPacket:
					default:
						t.Fatal("remaining receive queue lost its wakeup")
					}
					ack := tc.receivedPacketHandler().GetAckFrame(protocol.Encryption1RTT, monotime.Now(), true)
					require.NotNil(t, ack)
					require.Equal(t, pn, ack.LargestAcked())
					require.False(t, tc.receivedPacketHandler().ShouldFlushACK())
				}
			})
		}
	}
}
