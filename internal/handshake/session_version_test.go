package handshake

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func sessionVersionExtra(version protocol.Version) []byte {
	b := binary.BigEndian.AppendUint32(quicvarint.Append(nil, clientSessionStateRevision), uint32(version))
	b = quicvarint.Append(b, 0)
	b = quicvarint.Append(b, 0)
	return addSessionStateExtraPrefix(b)
}

func TestSessionMetadataIncludesOnlyMeasuredRTT(t *testing.T) {
	stats := utils.NewRTTStats()
	setup := &cryptoSetup{version: protocol.Version2, rttStats: stats}
	info, ok := SessionInfo([][]byte{addSessionStateExtraPrefix(setup.marshalDataForSessionState(false))})
	require.True(t, ok)
	require.Zero(t, info.RTT)
	stats.UpdateRTT(37*time.Millisecond+999*time.Microsecond, 0)
	info, ok = SessionInfo([][]byte{addSessionStateExtraPrefix(setup.marshalDataForSessionState(false))})
	require.True(t, ok)
	require.Equal(t, stats.SmoothedRTT(), info.RTT)
}

func TestSessionVersionMetadata(t *testing.T) {
	for _, version := range []protocol.Version{protocol.Version1, protocol.Version2} {
		got, ok := SessionVersion([][]byte{[]byte("unrelated"), sessionVersionExtra(version)})
		require.True(t, ok)
		require.Equal(t, version, got)
	}
	for _, extras := range [][][]byte{nil, {[]byte("unrelated")}, {[]byte(extraPrefix)}, {sessionVersionExtra(99)}, {sessionVersionExtra(protocol.Version1), sessionVersionExtra(protocol.Version2)}} {
		_, ok := SessionVersion(extras)
		require.False(t, ok)
	}
}

func TestSessionVersionMetadataRetainsOlderSessionEncoding(t *testing.T) {
	_, err := decodeDataFromSessionState([]byte{5}, false)
	require.NoError(t, err)
	_, err = decodeDataFromSessionState([]byte{6}, false)
	require.Error(t, err)
	legacy := (&wire.TransportParameters{InitialMaxData: 1234, ActiveConnectionIDLimit: 2}).MarshalForSessionTicket([]byte{5})
	parameters, err := decodeDataFromSessionState(legacy, true)
	require.NoError(t, err)
	require.EqualValues(t, 1234, parameters.InitialMaxData)
}

func TestSessionMetadataTruncationAndLegacyRevision(t *testing.T) {
	setup := &cryptoSetup{version: protocol.Version2, initialConnID: protocol.ParseConnectionID([]byte("cid")), rttStats: utils.NewRTTStats()}
	encoded := setup.marshalDataForSessionState(false)
	for n := 0; n < len(encoded); n++ {
		_, ok := SessionInfo([][]byte{addSessionStateExtraPrefix(encoded[:n])})
		require.False(t, ok, "truncated metadata at %d", n)
		_, err := decodeDataFromSessionState(encoded[:n], false)
		require.Error(t, err, "truncated cached state at %d", n)
	}
	_, err := decodeDataFromSessionState(encoded, false)
	require.NoError(t, err)
	legacy := binary.BigEndian.AppendUint32([]byte{6}, uint32(protocol.Version2))
	params := &wire.TransportParameters{InitialMaxData: 1234, ActiveConnectionIDLimit: 2}
	legacy = params.MarshalForSessionTicket(legacy)
	decoded, err := decodeDataFromSessionState(legacy, true)
	require.NoError(t, err)
	require.EqualValues(t, 1234, decoded.InitialMaxData)
	info, ok := SessionInfo([][]byte{addSessionStateExtraPrefix(legacy)})
	require.True(t, ok)
	require.Equal(t, protocol.Version2, info.Version)
	require.Zero(t, info.RTT)
	require.Empty(t, info.ConnectionID)
	oversize := binary.BigEndian.AppendUint32([]byte{7}, uint32(protocol.Version1))
	oversize = append(oversize, 0, protocol.MaxConnIDLen+1)
	oversize = append(oversize, make([]byte, protocol.MaxConnIDLen+1)...)
	_, ok = SessionInfo([][]byte{addSessionStateExtraPrefix(oversize)})
	require.False(t, ok)
	_, err = decodeDataFromSessionState(oversize, false)
	require.Error(t, err)
}
