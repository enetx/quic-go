package quic

import (
	"crypto/tls"
	"encoding/binary"
	"testing"
	"time"

	"github.com/enetx/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestClientSessionVersion(t *testing.T) {
	_, ok := SessionVersion(nil)
	require.False(t, ok)
	for _, version := range []Version{Version1, Version2} {
		extra := binary.BigEndian.AppendUint32(append([]byte("quic-go1"), 6), uint32(version))
		session, err := tls.NewResumptionState([]byte("ticket"), &tls.SessionState{Extra: [][]byte{extra}})
		require.NoError(t, err)
		got, ok := SessionVersion(session)
		require.True(t, ok)
		require.Equal(t, version, got)
	}
	session, err := tls.NewResumptionState([]byte("ticket"), &tls.SessionState{})
	require.NoError(t, err)
	_, ok = SessionVersion(session)
	require.False(t, ok)
}

func TestClientSessionMetadata(t *testing.T) {
	rtt := 42*time.Millisecond + 123*time.Microsecond
	extra := binary.BigEndian.AppendUint32(append([]byte("quic-go1"), 7), uint32(Version2))
	extra = quicvarint.Append(extra, uint64(rtt))
	extra = append(extra, 3, 'c', 'i', 'd')
	extra = append(extra, 1, 2, 3)
	session, err := tls.NewResumptionState([]byte("ticket"), &tls.SessionState{Extra: [][]byte{[]byte("application"), extra}})
	require.NoError(t, err)
	info, ok := ClientSessionMetadata(session)
	require.True(t, ok)
	require.Equal(t, Version2, info.Version)
	require.Equal(t, rtt, info.RTT)
	require.Equal(t, []byte("cid"), info.ConnectionID)
	require.Equal(t, []byte{1, 2, 3}, info.TransportParameters)
	info.TransportParameters[0] = 99
	info.ConnectionID[0] = 99
	again, ok := ClientSessionMetadata(session)
	require.True(t, ok)
	require.Equal(t, byte(1), again.TransportParameters[0])
	require.Equal(t, []byte("cid"), again.ConnectionID)
	version, ok := SessionVersion(session)
	require.True(t, ok)
	require.Equal(t, Version2, version)
}
