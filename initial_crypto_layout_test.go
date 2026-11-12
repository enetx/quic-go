package quic

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/enetx/quic-go/internal/handshake"
	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestInitialCryptoLayoutRanges(t *testing.T) {
	for _, ech := range []bool{false, true} {
		t.Run(fmt.Sprint(ech), func(t *testing.T) {
			hello, err := getClientHello("layout.quic-go.net")
			if ech {
				hello, err = getClientHelloWithECH("layout.quic-go.net")
			}
			require.NoError(t, err)
			original := bytes.Clone(hello)
			str := newInitialCryptoStream(true)
			var calls int
			layout := [][]CryptoRange{{{Offset: len(hello) - 19, Length: 19}, {Offset: 0, Length: 11}}, {{Offset: 11, Length: len(hello) - 30}}}
			str.layout = func(info InitialCryptoLayoutInfo) [][]CryptoRange {
				calls++
				if calls > 1 {
					return [][]CryptoRange{info.Remaining}
				}
				require.Equal(t, len(hello), info.Length)
				require.Equal(t, "layout.quic-go.net", string(hello[info.SNIOffset:info.SNIOffset+info.SNILength]))
				require.Equal(t, 1236, info.PacketSizeLimit)
				require.Equal(t, 1180, info.FrameBudget)
				if ech {
					require.Positive(t, info.ECHOffset)
					require.Greater(t, info.ECHLength, 4)
					require.LessOrEqual(t, info.ECHOffset+info.ECHLength, len(hello))
				} else {
					require.Equal(t, -1, info.ECHOffset)
					require.Zero(t, info.ECHLength)
				}
				return layout
			}
			for _, part := range [][]byte{hello[:2], hello[2 : len(hello)-1]} {
				_, err := str.Write(part)
				require.NoError(t, err)
				require.False(t, str.HasData(), "do not prepare an incomplete ClientHello")
			}
			_, err = str.Write(hello[len(hello)-1:])
			require.NoError(t, err)
			require.True(t, str.HasData())
			require.NoError(t, str.prepareInitialCryptoLayout(1236, 1180))
			require.Equal(t, 1, calls)
			// Both the outer and inner caller-owned slices can change afterwards.
			layout[0][0] = CryptoRange{Offset: 0, Length: 1}
			layout[1] = nil
			rng := rand.New(rand.NewPCG(1, 2))
			str.beginProtectedPacket(1180, rng)
			first := str.PopCryptoFrame(1180)
			second := str.PopCryptoFrame(1180)
			require.EqualValues(t, len(hello)-19, first.Offset)
			require.Equal(t, original[len(hello)-19:], first.Data)
			require.Zero(t, second.Offset)
			require.Equal(t, original[:11], second.Data)
			require.Nil(t, str.PopCryptoFrame(1180), "explicit group ends this packet")
			require.True(t, str.HasData())
			require.NoError(t, str.prepareInitialCryptoLayout(1235, 1179))
			str.beginProtectedPacket(1180, rng)
			var assembled []byte
			for str.HasData() {
				frame := str.PopCryptoFrame(37)
				require.NotNil(t, frame)
				require.EqualValues(t, 11+len(assembled), frame.Offset)
				require.LessOrEqual(t, frame.Length(protocol.Version1), protocol.ByteCount(37))
				assembled = append(assembled, frame.Data...)
			}
			require.Equal(t, original[11:len(hello)-19], assembled)
			require.Equal(t, original, hello)
			_, err = str.Write([]byte("second hello"))
			require.NoError(t, err)
			require.NoError(t, str.prepareInitialCryptoLayout(1236, 1180))
			str.beginProtectedPacket(1180, rng)
			next := str.PopCryptoFrame(1180)
			require.EqualValues(t, len(hello), next.Offset)
			require.Equal(t, "second hello", string(next.Data))
			require.Equal(t, 2, calls, "later Initial writes keep native offsets")
		})
	}
}

func TestInitialCryptoLayoutValidation(t *testing.T) {
	hello, err := getClientHello("layout.quic-go.net")
	require.NoError(t, err)
	for name, layout := range map[string][][]CryptoRange{
		"empty": {}, "empty packet": {{}},
		"negative offset": {{{Offset: -1, Length: len(hello)}}},
		"zero length":     {{{Offset: 0, Length: 0}}},
		"negative length": {{{Offset: 0, Length: -1}}},
		"beyond end":      {{{Offset: len(hello), Length: 1}}},
		"length overflow": {{{Offset: 1, Length: int(^uint(0) >> 1)}}},
		"missing prefix":  {{{Offset: 1, Length: len(hello) - 1}}},
		"missing suffix":  {{{Offset: 0, Length: len(hello) - 1}}},
		"overlap":         {{{Offset: 0, Length: len(hello)}}, {{Offset: 1, Length: 1}}},
		"gap":             {{{Offset: 0, Length: 11}}, {{Offset: 12, Length: len(hello) - 12}}},
	} {
		t.Run(name, func(t *testing.T) {
			str := newInitialCryptoStream(true)
			str.layout = func(InitialCryptoLayoutInfo) [][]CryptoRange { return layout }
			_, err := str.Write(hello)
			require.NoError(t, err)
			require.ErrorContains(t, str.prepareInitialCryptoLayout(1236, 1180), "Initial CRYPTO layout")
			require.Nil(t, str.protection)
			require.Zero(t, str.writeOffset, "invalid layout cannot consume crypto bytes")
			require.Equal(t, hello, str.writeBuf)
		})
	}
}

func TestInitialCryptoLayoutNilRetainsNative(t *testing.T) {
	for _, hostname := range []string{"", "layout.quic-go.net"} {
		t.Run(hostname, func(t *testing.T) {
			hello, err := getClientHello(hostname)
			require.NoError(t, err)
			native, custom := newInitialCryptoStream(true), newInitialCryptoStream(true)
			custom.layout = func(info InitialCryptoLayoutInfo) [][]CryptoRange {
				if hostname == "" {
					require.Equal(t, -1, info.SNIOffset)
					require.Zero(t, info.SNILength)
				}
				return nil
			}
			_, err = native.Write(hello)
			require.NoError(t, err)
			_, err = custom.Write(hello)
			require.NoError(t, err)
			require.NoError(t, custom.prepareInitialCryptoLayout(1236, 1180))
			for native.HasData() {
				require.True(t, custom.HasData())
				require.Equal(t, native.PopCryptoFrame(100), custom.PopCryptoFrame(100))
			}
			require.False(t, custom.HasData())
		})
	}
}

func TestInitialCryptoLayoutPacketPreparation(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprint(invalid), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
			hello, err := getClientHello("layout.quic-go.net")
			require.NoError(t, err)
			var snapshot InitialCryptoLayoutInfo
			tp.initialStream.layout = func(info InitialCryptoLayoutInfo) [][]CryptoRange {
				snapshot = info
				if invalid {
					return [][]CryptoRange{{{Offset: 1, Length: len(hello) - 1}}}
				}
				return [][]CryptoRange{{{Offset: len(hello) - 19, Length: 19}, {Offset: 0, Length: 11}}, {{Offset: 11, Length: len(hello) - 30}}}
			}
			_, err = tp.initialStream.Write(hello)
			require.NoError(t, err)
			tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(ctrl), nil)
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}
			tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), false).Return(ack)
			tp.pnManager.EXPECT().PeekPacketNumber(protocol.PacketNumberSpaceInitial).Return(protocol.PacketNumber(1), protocol.PacketNumberLen1)
			if !invalid {
				tp.pnManager.EXPECT().PopPacketNumber(protocol.PacketNumberSpaceInitial).Return(protocol.PacketNumber(1))
				tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				tp.sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
			}
			packet, err := tp.packer.PackCoalescedPacket(false, 1250, monotime.Now(), protocol.Version1)
			if invalid {
				require.ErrorContains(t, err, "Initial CRYPTO layout")
				require.Nil(t, packet)
				return
			}
			require.NoError(t, err)
			defer packet.buffer.Release()
			require.Equal(t, 1243, snapshot.PacketSizeLimit, "live limit excludes mock AEAD expansion")
			require.Equal(t, 1243-int(packet.longHdrPackets[0].header.GetLength(protocol.Version1))-int(ack.Length(protocol.Version1)), snapshot.FrameBudget)
			require.Len(t, packet.longHdrPackets[0].frames, 2)
			first := packet.longHdrPackets[0].frames[0].Frame.(*wire.CryptoFrame)
			second := packet.longHdrPackets[0].frames[1].Frame.(*wire.CryptoFrame)
			require.EqualValues(t, len(hello)-19, first.Offset)
			require.Equal(t, hello[len(hello)-19:], first.Data)
			require.Zero(t, second.Offset)
			require.Equal(t, hello[:11], second.Data)
			// The mock does no encryption or header protection, so decode the
			// actual packet bytes as well as inspecting the recovery frames.
			header := packet.longHdrPackets[0].header
			raw := packet.buffer.Data[header.GetLength(protocol.Version1) : packet.buffer.Len()-7]
			parser := wire.NewFrameParser(false, false, false)
			var wireCrypto []*wire.CryptoFrame
			for len(raw) > 0 {
				kind, n, err := parser.ParseType(raw, protocol.EncryptionInitial)
				raw = raw[n:]
				if err != nil {
					break
				} // remaining PADDING
				if kind.IsAckFrameType() {
					_, n, err := parser.ParseAckFrame(kind, raw, protocol.EncryptionInitial, protocol.Version1)
					require.NoError(t, err)
					raw = raw[n:]
					continue
				}
				frame, n, err := parser.ParseLessCommonFrame(kind, raw, protocol.Version1)
				require.NoError(t, err)
				raw = raw[n:]
				if crypto, ok := frame.(*wire.CryptoFrame); ok {
					wireCrypto = append(wireCrypto, crypto)
				}
			}
			require.Equal(t, []*wire.CryptoFrame{first, second}, wireCrypto)
		})
	}
}
