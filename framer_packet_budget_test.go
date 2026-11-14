package quic

import (
	"fmt"
	"testing"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func smallTailFramer(t *testing.T, creation bool, offset int) *framer {
	t.Helper()
	tc := newClientTestConnection(t, nil, &Config{
		ClientHandshake: &ClientHandshake{StreamSchedulingByCreation: creation},
	}, true)
	tc.conn.restoreTransportParameters(&wire.TransportParameters{
		ActiveConnectionIDLimit: 2, InitialMaxData: 8192,
		InitialMaxStreamDataUni: 4096, InitialMaxStreamDataBidiRemote: 4096,
		MaxUniStreamNum: 3, MaxBidiStreamNum: 3,
	})
	control, err := tc.conn.OpenUniStream()
	require.NoError(t, err)
	request, err := tc.conn.OpenStream()
	require.NoError(t, err)
	framer := tc.conn.framer

	if offset > 0 {
		require.NoError(t, control.TryWriteAll(make([]byte, offset)))
		_, sent, _ := framer.appendStreamFrames(nil, nil, 400, 1, protocol.Version1)
		require.Len(t, sent, 1)
		require.Len(t, sent[0].Frame.Data, offset)
	}
	require.NoError(t, control.TryWriteAll(make([]byte, 100)))
	require.NoError(t, request.sendStr.TryWriteAll(make([]byte, 100)))
	return framer
}

func TestSmallStreamTailRespectsLengthVarintBoundary(t *testing.T) {
	for _, creation := range []bool{false, true} {
		for _, retransmit := range []bool{false, true} {
			for _, offset := range []int{0, 64} {
				for _, budget := range []protocol.ByteCount{2, 3, 4, 5, 63, 64, 65, 66, 67, 127, 128, 129, 130, 131, 132} {
					name := fmt.Sprintf("creation=%t/retransmit=%t/offset=%d/budget=%d", creation, retransmit, offset, budget)
					t.Run(name, func(t *testing.T) {
						framer := smallTailFramer(t, creation, offset)
						expectedData := 200
						if retransmit {
							_, frames, _ := framer.appendStreamFrames(nil, nil, 400, 1, protocol.Version1)
							require.NotEmpty(t, frames)
							expectedData = len(frames[0].Frame.Data)
							frames[0].Handler.OnLost(frames[0].Frame)
						}

						_, frames, length := framer.appendStreamFrames(nil, nil, budget, 1, protocol.Version1)
						if budget >= 5 {
							require.NotEmpty(t, frames)
						}
						var encoded []byte
						var data int
						for _, frame := range frames {
							var err error
							encoded, err = frame.Frame.Append(encoded, protocol.Version1)
							require.NoError(t, err)
							data += len(frame.Frame.Data)
						}
						require.EqualValues(t, len(encoded), length)
						require.LessOrEqual(t, len(encoded), int(budget))

						_, remaining, _ := framer.appendStreamFrames(nil, nil, 400, 1, protocol.Version1)
						for _, frame := range remaining {
							data += len(frame.Frame.Data)
						}
						require.Equal(t, expectedData, data, "sizing must not lose or repeat stream bytes")
					})
				}
			}
		}
	}
}
