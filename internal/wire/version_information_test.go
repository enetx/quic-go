package wire

import (
	"encoding/binary"
	"testing"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func versionBytes(versions ...protocol.Version) []byte {
	var b []byte
	for _, v := range versions {
		b = binary.BigEndian.AppendUint32(b, uint32(v))
	}
	return b
}

func TestVersionInformationCodec(t *testing.T) {
	for _, pers := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
		want := &VersionInformation{Chosen: protocol.Version1, Available: []protocol.Version{0x0a1a2a3a, protocol.Version2, protocol.Version1}}
		p := &TransportParameters{VersionInformation: want, MaxDatagramFrameSize: protocol.InvalidByteCount, ActiveConnectionIDLimit: 2}
		data := p.Marshal(pers)
		var got TransportParameters
		require.NoError(t, got.Unmarshal(data, pers))
		require.Equal(t, want, got.VersionInformation)
		// Negotiated capability is not remembered as a 0-RTT transport limit.
		var ticket TransportParameters
		require.NoError(t, ticket.UnmarshalFromSessionTicket(p.MarshalForSessionTicket(nil)))
		require.Nil(t, ticket.VersionInformation)
	}
	server, err := ParseVersionInformation(versionBytes(protocol.Version2), protocol.PerspectiveServer)
	require.NoError(t, err)
	require.Empty(t, server.Available)
	_, err = ParseVersionInformation(versionBytes(protocol.Version2), protocol.PerspectiveClient)
	require.Error(t, err)
}

func TestVersionInformationRejectsMalformedAndDuplicate(t *testing.T) {
	for _, data := range [][]byte{nil, {1}, {0, 0, 0}, make([]byte, 4), {0, 0, 0, 1, 0}, versionBytes(protocol.Version1, 0), versionBytes(protocol.Version1, protocol.Version2)} {
		_, err := ParseVersionInformation(data, protocol.PerspectiveClient)
		require.Error(t, err)
	}
	value := versionBytes(protocol.Version1, protocol.Version1)
	param := quicvarint.Append(nil, 0x11)
	param = quicvarint.Append(param, uint64(len(value)))
	param = append(param, value...)
	var p TransportParameters
	require.Error(t, p.Unmarshal(append(param, param...), protocol.PerspectiveClient))
}
