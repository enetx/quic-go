package quic

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestInitialCryptoLayoutUsesActualUnsentBytesAndBudgets(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		t.Run(fmt.Sprint(fallback), func(t *testing.T) {
			hello, err := getClientHello("layout.quic-go.net")
			require.NoError(t, err)
			str := newInitialCryptoStream(true)
			var snapshots []InitialCryptoLayoutInfo
			str.layout = func(info InitialCryptoLayoutInfo) [][]CryptoRange {
				copyInfo := info
				copyInfo.Remaining = slices.Clone(info.Remaining)
				snapshots = append(snapshots, copyInfo)
				if fallback && len(snapshots) > 1 {
					return nil // sequential remaining, not the already-drained buffer
				}
				ranges := slices.Clone(info.Remaining)
				slices.Reverse(ranges)
				// Callback input is a snapshot as well as callback results.
				info.Remaining[0] = CryptoRange{Offset: -100, Length: -100}
				return [][]CryptoRange{ranges}
			}
			_, err = str.Write(hello)
			require.NoError(t, err)
			assembled, seen := make([]byte, len(hello)), make([]bool, len(hello))
			rng := rand.New(rand.NewPCG(1, 2))
			previous := bytes.Clone(hello)
			for packet := 0; str.HasData(); packet++ {
				require.Less(t, packet, len(hello), "custom layout must make progress")
				budget := protocol.ByteCount([]int{37, 19, 81, 67}[packet%4])
				require.NoError(t, str.prepareInitialCryptoLayout(1200+protocol.ByteCount(packet), budget))
				info := snapshots[len(snapshots)-1]
				require.EqualValues(t, 1200+packet, info.PacketSizeLimit)
				require.EqualValues(t, budget, info.FrameBudget)
				for _, part := range info.Remaining {
					for i := part.Offset; i < part.Offset+part.Length; i++ {
						require.False(t, seen[i], "callback cannot see bytes already queued in prior packets")
					}
				}
				str.beginProtectedPacket(budget, rng)
				remaining := budget
				progress := 0
				for {
					frame := str.PopCryptoFrame(remaining)
					if frame == nil {
						break
					}
					remaining -= frame.Length(protocol.Version1)
					require.GreaterOrEqual(t, remaining, protocol.ByteCount(0))
					for i, b := range frame.Data {
						offset := int(frame.Offset) + i
						require.False(t, seen[offset], "no duplicated ClientHello byte")
						seen[offset], assembled[offset] = true, b
					}
					progress += len(frame.Data)
				}
				require.Positive(t, progress)
			}
			require.Greater(t, len(snapshots), 2, "budgets are re-evaluated over several packets")
			require.Equal(t, previous, assembled)
			for _, present := range seen {
				require.True(t, present)
			}
			require.Nil(t, str.layoutState, "release the full handshake buffer when all custom ranges are consumed")
		})
	}
}

func TestInitialCryptoLayoutCannotReintroduceSentBytes(t *testing.T) {
	hello, err := getClientHello("layout.quic-go.net")
	require.NoError(t, err)
	str := newInitialCryptoStream(true)
	calls := 0
	str.layout = func(info InitialCryptoLayoutInfo) [][]CryptoRange {
		calls++
		if calls == 1 {
			return [][]CryptoRange{{{Length: 11}}, {{Offset: 11, Length: info.Length - 11}}}
		}
		return [][]CryptoRange{{{Length: info.Length}}}
	}
	_, err = str.Write(hello)
	require.NoError(t, err)
	require.NoError(t, str.prepareInitialCryptoLayout(1236, 1210))
	str.beginProtectedPacket(1210, rand.New(rand.NewPCG(1, 2)))
	frame := str.PopCryptoFrame(1210)
	require.Equal(t, hello[:11], frame.Data)
	require.Nil(t, str.PopCryptoFrame(1210))
	require.ErrorContains(t, str.prepareInitialCryptoLayout(1235, 1209), "Initial CRYPTO layout")
	require.Equal(t, []CryptoRange{{Offset: 11, Length: len(hello) - 11}}, str.layoutState.remaining)
}

func TestInitialCryptoLayoutClientOnly(t *testing.T) {
	for _, perspective := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
		config := populateConfig(&Config{ClientHandshake: &ClientHandshake{InitialCryptoLayout: func(InitialCryptoLayoutInfo) [][]CryptoRange { return nil }}})
		conn := &Conn{config: config, perspective: perspective, initialStream: newInitialCryptoStream(perspective == protocol.PerspectiveClient)}
		conn.configureInitialCryptoStream()
		require.Equal(t, perspective == protocol.PerspectiveClient, conn.initialStream.layout != nil)
		require.NotNil(t, config.Clone().ClientHandshake.InitialCryptoLayout, "config snapshots retain policy callbacks")
	}
}
