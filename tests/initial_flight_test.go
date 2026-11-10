package quic_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/stretchr/testify/require"
)

type initialFlightPacketConn struct {
	net.PacketConn
	drop   int32
	writes atomic.Int32
}

func (c *initialFlightPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.writes.Add(1) == c.drop {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

func TestInitialFlightRecoversLossAndPreservesCoalescedAEAD(t *testing.T) {
	for _, separate := range []bool{false, true} {
		for _, drop := range []int32{0, 1, 2, 3} {
			t.Run(fmt.Sprintf("separate=%v/drop=%d", separate, drop), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				serverTLS := testdata.GetTLSConfig()
				serverTLS.NextProtos = []string{"initial-flight"}
				listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
				require.NoError(t, err)
				defer listener.Close()
				udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
				require.NoError(t, err)
				defer udp.Close()
				packet := &initialFlightPacketConn{PacketConn: udp, drop: drop}
				transport := &quic.Transport{Conn: packet}
				defer transport.Close()
				payload := []byte("verified application data in the first post-handshake flight")
				staged := make(chan error, 1)
				config := &quic.Config{DisablePathMTUDiscovery: true, InitialPacketSize: 1252, ClientHandshake: &quic.ClientHandshake{
					InitialPaddingMode: quic.InitialPaddingDatagram, HandshakeAckBeforeData: separate,
					OnApplicationReady: func(c *quic.Conn) {
						stream, err := c.OpenUniStream()
						if err == nil {
							err = stream.TryWriteAll(payload)
							if err == nil {
								err = stream.Close()
							}
						}
						staged <- err
					},
				}}
				client, err := transport.Dial(ctx, listener.Addr(), &tls.Config{ServerName: "localhost", RootCAs: testdata.GetRootCA(), NextProtos: []string{"initial-flight"}, CurvePreferences: []tls.CurveID{tls.X25519}}, config)
				require.NoError(t, err)
				defer client.CloseWithError(0, "")
				require.NoError(t, <-staged)
				server, err := listener.Accept(ctx)
				require.NoError(t, err)
				defer server.CloseWithError(0, "")
				stream, err := server.AcceptUniStream(ctx)
				require.NoError(t, err)
				deadline, _ := ctx.Deadline()
				stream.SetReadDeadline(deadline)
				body, err := io.ReadAll(stream)
				require.NoError(t, err)
				require.Equal(t, payload, body)
			})
		}
	}
}
