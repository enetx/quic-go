package quic

import (
	"bytes"
	"fmt"
	"io"
	"math/rand/v2"
	"testing"

	"github.com/enetx/quic-go/internal/ackhandler"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestProtectedClientHelloReassembly(t *testing.T) {
	for _, size := range []int{60, 1200, 1700, 4000, 65000} {
		for _, budget := range []int{64, 1190, 1400} {
			t.Run(fmt.Sprintf("%d/%d", size, budget), func(t *testing.T) {
				data := make([]byte, size)
				for i := range data {
					data[i] = byte(i*131 + i/251)
				}
				data[0], data[1], data[2], data[3] = 1, byte((size-4)>>16), byte((size-4)>>8), byte(size-4)
				s := newInitialCryptoStream(true)
				s.scramble = false
				s.protection = &initialProtectionState{policy: InitialPacketProtection{MinFirstFrameSize: 55, MaxFirstFrameSize: 86}}
				s.Write(data[:3])
				require.False(t, s.HasData(), "partial TLS handshake header")
				s.Write(data[3 : size-1])
				require.False(t, s.HasData(), "incomplete ClientHello")
				s.Write(data[size-1:])
				rng := rand.New(rand.NewPCG(1, 2))
				reassembled := make([]byte, size)
				seen := make([]bool, size)
				for packet := 0; s.HasData(); packet++ {
					require.Less(t, packet, size, "packetization stalled")
					s.beginProtectedPacket(protocol.ByteCount(budget), rng)
					remaining := protocol.ByteCount(budget)
					progress := 0
					for s.HasData() {
						f := s.PopCryptoFrame(remaining)
						if f == nil {
							break
						}
						require.LessOrEqual(t, f.Length(protocol.Version1), remaining)
						remaining -= f.Length(protocol.Version1)
						for i, b := range f.Data {
							offset := int(f.Offset) + i
							require.Less(t, offset, size)
							require.False(t, seen[offset], "duplicate crypto byte")
							seen[offset], reassembled[offset] = true, b
						}
						progress += len(f.Data)
					}
					require.Positive(t, progress)
				}
				require.Equal(t, data, reassembled)
				for _, present := range seen {
					require.True(t, present)
				}
				s.Write([]byte("second hello"))
				s.beginProtectedPacket(protocol.ByteCount(budget), rng)
				f := s.PopCryptoFrame(protocol.ByteCount(budget))
				require.EqualValues(t, size, f.Offset)
				require.Equal(t, "second hello", string(f.Data))
			})
		}
	}
}

func TestInitialProtectionPreservesWireBudgetAndRecovery(t *testing.T) {
	for seed := uint64(0); seed < 100; seed++ {
		for _, padding := range []int{0, 1, 20, 500} {
			data := make([]byte, 1000)
			for i := range data {
				data[i] = byte(i*37 + i/251 + int(seed))
			}
			expected := bytes.Clone(data)
			original := &wire.CryptoFrame{Data: data}
			queue := newRetransmissionQueue()
			pl := payload{length: original.Length(protocol.Version1), frames: []ackhandler.Frame{{Frame: original, Handler: queue.AckHandler(protocol.EncryptionInitial)}}}
			p := &packetPacker{rand: *rand.New(rand.NewPCG(seed, 3)), initialProtection: &InitialPacketProtection{MinCryptoSplits: 2, MaxCryptoSplits: 10, MinPingFrames: 2, MaxPingFrames: 10}}
			raw, result, err := p.appendProtectedInitial(nil, pl, protocol.ByteCount(padding), protocol.Version1)
			require.NoError(t, err)
			require.Len(t, raw, int(pl.length)+padding)
			require.EqualValues(t, 0, original.Offset)
			require.Equal(t, expected, original.Data)
			parser := wire.NewFrameParser(false, false, false)
			reassembled := make([]byte, len(data))
			seen := make([]bool, len(data))
			for len(raw) > 0 {
				kind, n, err := parser.ParseType(raw, protocol.EncryptionInitial)
				raw = raw[n:]
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
				frame, n, err := parser.ParseLessCommonFrame(kind, raw, protocol.Version1)
				require.NoError(t, err)
				raw = raw[n:]
				if f, ok := frame.(*wire.CryptoFrame); ok {
					for i, b := range f.Data {
						offset := int(f.Offset) + i
						require.False(t, seen[offset])
						seen[offset], reassembled[offset] = true, b
					}
				}
			}
			require.Equal(t, expected, reassembled)
			for _, present := range seen {
				require.True(t, present)
			}
			for _, f := range result.frames {
				f.Handler.OnLost(f.Frame)
			}
			recovered := make([]byte, len(data))
			for queue.HasData(protocol.EncryptionInitial) {
				frame := queue.GetFrame(protocol.EncryptionInitial, 2000, protocol.Version1)
				f, ok := frame.(*wire.CryptoFrame)
				require.True(t, ok, "protection PING must not be retransmitted")
				copy(recovered[int(f.Offset):], f.Data)
			}
			require.Equal(t, expected, recovered)
		}
	}
}

func TestReceiveWindowUpdateDivisors(t *testing.T) {
	for _, divisor := range []uint32{2, 4} {
		c := receiveFlowController{receiveWindow: 1200, receiveWindowSize: 1200, updateDivisor: divisor}
		c.addBytesRead(1200 / protocol.ByteCount(divisor))
		require.False(t, c.hasWindowUpdate(), "strict browser boundary")
		c.addBytesRead(1)
		require.True(t, c.hasWindowUpdate())
	}
}
