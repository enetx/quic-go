package quic

import (
	"crypto/tls"
	"encoding/binary"
	"testing"

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
