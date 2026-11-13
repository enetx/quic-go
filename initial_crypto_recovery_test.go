package quic

import (
	"bytes"
	"math/rand/v2"
	"testing"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestInitialCryptoRecoveryCoalescesAndRetiresCopies(t *testing.T) {
	r := &cryptoRangeRecovery{data: bytes.Repeat([]byte{0x42}, 1000)}
	frame := func(off, n int) *wire.CryptoFrame {
		return &wire.CryptoFrame{Offset: protocol.ByteCount(off), Data: r.data[off : off+n]}
	}
	r.OnLost(frame(500, 500))
	r.OnLost(frame(0, 700))
	r.OnLost(frame(100, 200))
	require.Equal(t, []CryptoRange{{Length: 1000}}, r.pending)
	r.OnAcked(frame(200, 300))
	require.Equal(t, []CryptoRange{{Length: 200}, {Offset: 500, Length: 500}}, r.pending)
	r.OnLost(frame(0, 1000))
	require.Equal(t, []CryptoRange{{Length: 200}, {Offset: 500, Length: 500}}, r.pending, "loss of another copy must not resurrect ACKed bytes")
	require.NoError(t, r.prepare(1236, 1210))
	first := r.pop(100)
	require.Zero(t, first.Offset)
	require.Less(t, len(first.Data), 100)
	r.OnAcked(frame(0, 1000))
	require.Empty(t, r.pending)
	require.Nil(t, r.pop(1210), "a late ACK invalidates a prepared group")
	r.close()
	r.OnLost(first)
	require.Nil(t, r.data)
	require.Empty(t, r.pending)
}

func TestInitialCryptoRecoveryRangeOperationsAgainstByteOracle(t *testing.T) {
	r := &cryptoRangeRecovery{data: make([]byte, 512)}
	acked, pending := make([]bool, 512), make([]bool, 512)
	rng := rand.New(rand.NewPCG(13, 29))
	for range 1000 {
		off := rng.IntN(512)
		n := 1 + rng.IntN(512-off)
		frame := &wire.CryptoFrame{Offset: protocol.ByteCount(off), Data: r.data[off : off+n]}
		if rng.IntN(4) == 0 {
			r.OnAcked(frame)
			for i := off; i < off+n; i++ {
				acked[i] = true
				pending[i] = false
			}
		} else {
			r.OnLost(frame)
			for i := off; i < off+n; i++ {
				pending[i] = !acked[i]
			}
		}
		actual := make([]bool, 512)
		end := -1
		for _, part := range r.pending {
			require.Greater(t, part.Offset, end, "pending ranges must be disjoint and coalesced")
			end = part.Offset + part.Length
			for i := part.Offset; i < end; i++ {
				actual[i] = true
			}
		}
		require.Equal(t, pending, actual)
	}
}

func TestInitialCryptoRecoveryLayoutPreservesOffsetsAfterHRR(t *testing.T) {
	hello, err := getClientHello("recovery.quic-go.net")
	require.NoError(t, err)
	second := bytes.Clone(hello)
	r := &cryptoRangeRecovery{data: append(bytes.Clone(hello), second...)}
	secondFrame := &wire.CryptoFrame{Offset: protocol.ByteCount(len(hello)), Data: second}
	r.OnLost(secondFrame)
	r.layout = func(info InitialCryptoLayoutInfo) [][]CryptoRange {
		require.Equal(t, 2*len(hello), info.Length)
		require.Equal(t, []CryptoRange{{Offset: len(hello), Length: len(hello)}}, info.Remaining)
		require.Equal(t, "recovery.quic-go.net", string(r.data[info.SNIOffset:info.SNIOffset+info.SNILength]))
		info.Remaining[0].Offset = 0 // callback snapshots must not modify recovery
		return nil
	}
	require.NoError(t, r.prepare(1236, 1210))
	f := r.pop(1210)
	require.EqualValues(t, len(hello), f.Offset)
	require.Equal(t, second[:len(f.Data)], f.Data)
	// Invalid plans fail before consuming any bytes.
	r.OnLost(secondFrame)
	before := append([]CryptoRange(nil), r.pending...)
	r.layout = func(info InitialCryptoLayoutInfo) [][]CryptoRange { return [][]CryptoRange{{{Length: len(hello)}}} }
	require.Error(t, r.prepare(1236, 1210))
	require.Equal(t, before, r.pending)
}

func TestInitialCryptoRecoveryConfiguration(t *testing.T) {
	for _, config := range []*ClientHandshake{
		{InitialCryptoRecoveryLayout: func(InitialCryptoLayoutInfo) [][]CryptoRange { return nil }},
		{InitialCryptoProbePackets: 2},
		{InitialCryptoRecovery: true, InitialCryptoProbePackets: 3},
	} {
		require.Error(t, config.Validate())
	}
	for _, n := range []uint8{0, 1, 2} {
		require.NoError(t, (&ClientHandshake{InitialCryptoRecovery: true, InitialCryptoProbePackets: n}).Validate())
	}
}

func TestInitialCryptoPeerProbeExcludesUnsentAndAckedBytes(t *testing.T) {
	r := &cryptoRangeRecovery{data: make([]byte, 1000), sent: []CryptoRange{{Length: 400}}, peerProbe: true}
	r.OnAcked(&wire.CryptoFrame{Offset: 100, Data: make([]byte, 100)})
	r.resendUnacked()
	require.Equal(t, []CryptoRange{{Length: 100}, {Offset: 200, Length: 200}}, r.pending)
	r.peerProbe = false
	r.pending = nil
	r.resendUnacked()
	require.Empty(t, r.pending)
	r.peerProbe = true
	r.close()
	r.resendUnacked()
	require.Empty(t, r.pending)
}
