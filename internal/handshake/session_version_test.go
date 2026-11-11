package handshake

import (
	"encoding/binary"
	"testing"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func sessionVersionExtra(version protocol.Version) []byte {
	b := binary.BigEndian.AppendUint32(quicvarint.Append(nil, clientSessionStateRevision), uint32(version))
	return addSessionStateExtraPrefix(b)
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
