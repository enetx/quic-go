package quic

import (
	"fmt"
	"testing"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestFINOnlyFrameRespectsSmallPacketBudget(t *testing.T) {
	for _, id := range []protocol.StreamID{0, 63, 64, 16384} {
		for _, offset := range []protocol.ByteCount{0, 63, 64, 16384} {
			t.Run(fmt.Sprintf("id=%d/offset=%d", id, offset), func(t *testing.T) {
				stream := &SendStream{streamID: id, writeOffset: offset, finishedWriting: true}
				fin := &wire.StreamFrame{StreamID: id, Offset: offset, DataLenPresent: true, Fin: true}
				length := fin.Length(protocol.Version1)
				for budget := protocol.ByteCount(0); budget < length; budget++ {
					frame, blocked, more := stream.popStreamFrame(budget, protocol.Version1)
					require.Nil(t, frame.Frame, "FIN exceeded budget %d", budget)
					require.Nil(t, blocked)
					require.True(t, more, "a deferred FIN must remain queued")
				}

				frame, blocked, more := stream.popStreamFrame(length, protocol.Version1)
				require.NotNil(t, frame.Frame)
				require.True(t, frame.Frame.Fin)
				require.Equal(t, length, frame.Frame.Length(protocol.Version1))
				require.Nil(t, blocked)
				require.False(t, more)
				frame, _, more = stream.popStreamFrame(length, protocol.Version1)
				require.Nil(t, frame.Frame, "the FIN must be transmitted exactly once")
				require.False(t, more)
			})
		}
	}
}
