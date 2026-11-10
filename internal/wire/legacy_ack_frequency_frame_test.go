package wire

import (
	"encoding/hex"
	"io"
	"math"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestLegacyAckFrequencyWire(t *testing.T) {
	// Independent Neqo frame.rs vector: seq=10, tolerance=5, delay=2000us,
	// followed by exactly one ignore_order byte, rather than a QUIC varint.
	// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/third_party/rust/neqo-transport/src/frame.rs
	encoded, err := hex.DecodeString("40af0a0547d001")
	require.NoError(t, err)
	f, n, err := parseLegacyAckFrequencyFrame(append(encoded[2:], 0x01))
	require.NoError(t, err)
	require.Equal(t, len(encoded)-2, n, "must leave following PING untouched")
	require.Equal(t, &LegacyAckFrequencyFrame{10, 5, 2 * time.Millisecond, true}, f)
	output, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, encoded, output)
	require.EqualValues(t, len(encoded), f.Length(protocol.Version1))
	for i := range len(encoded) - 2 {
		_, _, err := parseLegacyAckFrequencyFrame(encoded[2 : 2+i])
		require.ErrorIs(t, err, io.EOF)
	}
	for _, value := range []byte{2, 3, 0x40, 0xff} {
		_, _, err := parseLegacyAckFrequencyFrame([]byte{0, 1, 1, value})
		require.Error(t, err)
	}
	_, _, err = parseLegacyAckFrequencyFrame([]byte{0, 0, 1, 0})
	require.Error(t, err)
	for _, delay := range []uint64{math.MaxInt64 / 1000, math.MaxInt64/1000 + 1, 1 << 61, quicvarint.Max} {
		data := quicvarint.Append([]byte{0, 1}, delay)
		f, _, err := parseLegacyAckFrequencyFrame(append(data, 0))
		require.NoError(t, err)
		require.Positive(t, f.RequestMaxAckDelay, "duration must never wrap")
	}
}

func TestLegacyAckFrequencyParserNegotiation(t *testing.T) {
	parser := NewFrameParser(false, false, false)
	_, _, err := parser.ParseType([]byte{0x40, 0xaf}, protocol.Encryption1RTT)
	require.Error(t, err)
	parser.SetLegacyAckFrequency(true)
	for _, level := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT} {
		_, _, err := parser.ParseType([]byte{0x40, 0xaf}, level)
		require.Error(t, err)
	}
	kind, n, err := parser.ParseType([]byte{0x40, 0xaf}, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameTypeAckFrequency, kind)
	require.Equal(t, 2, n)
	frame, _, err := parser.ParseLessCommonFrame(kind, []byte{0, 2, 1, 1}, protocol.Version1)
	require.NoError(t, err)
	require.IsType(t, &LegacyAckFrequencyFrame{}, frame)
	_, _, err = parser.ParseType([]byte{byte(FrameTypeImmediateAck)}, protocol.Encryption1RTT)
	require.Error(t, err, "legacy negotiation must not enable the newer IMMEDIATE_ACK extension")
}
