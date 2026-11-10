package quic_test

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/stretchr/testify/require"
)

func TestClientPacketFactoriesFailBeforeSending(t *testing.T) {
	failure := errors.New("packet factory failed")
	for name, handshake := range map[string]*quic.ClientHandshake{
		"cid-size":     {NewInitialDestinationConnectionIDLength: func() (int, error) { return 7, nil }},
		"cid-error":    {NewInitialDestinationConnectionIDLength: func() (int, error) { return 0, failure }},
		"packet-size":  {NewInitialPacketSize: func(net.Addr) (uint16, error) { return 1199, nil }},
		"packet-large": {NewInitialPacketSize: func(net.Addr) (uint16, error) { return 65535, nil }},
		"packet-error": {NewInitialPacketSize: func(net.Addr) (uint16, error) { return 0, failure }},
	} {
		t.Run(name, func(t *testing.T) {
			peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer peer.Close()
			conn, err := quic.DialAddr(t.Context(), peer.LocalAddr().String(), &tls.Config{ServerName: "localhost"}, &quic.Config{ClientHandshake: handshake})
			require.Nil(t, conn)
			require.Error(t, err)
			require.ErrorContains(t, err, "factory")
			if name == "cid-error" || name == "packet-error" {
				require.ErrorIs(t, err, failure)
			}
			require.NoError(t, peer.SetReadDeadline(time.Now().Add(10*time.Millisecond)))
			_, _, err = peer.ReadFrom(make([]byte, 2048))
			var timeout net.Error
			require.ErrorAs(t, err, &timeout)
			require.True(t, timeout.Timeout(), "factory failure must not emit a UDP packet")
		})
	}
}
