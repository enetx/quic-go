package quic

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/testdata"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/stretchr/testify/require"
)

func peerAckFrequencyConnectionPair(t *testing.T, ctx context.Context, serverConfig, clientConfig *Config) (*Conn, *Conn) {
	t.Helper()
	serverTLS := testdata.GetTLSConfig()
	serverTLS.NextProtos = []string{"peer-ack-frequency-test"}
	serverUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { serverUDP.Close() })
	serverTransport := &Transport{Conn: serverUDP}
	t.Cleanup(func() { serverTransport.Close() })
	listener, err := serverTransport.Listen(serverTLS, serverConfig)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	clientUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { clientUDP.Close() })
	clientTransport := &Transport{Conn: clientUDP}
	t.Cleanup(func() { clientTransport.Close() })
	client, err := clientTransport.Dial(ctx, listener.Addr(), &tls.Config{ServerName: "localhost", RootCAs: testdata.GetRootCA(), NextProtos: serverTLS.NextProtos}, clientConfig)
	require.NoError(t, err)
	t.Cleanup(func() { client.CloseWithError(0, "") })
	server, err := listener.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { server.CloseWithError(0, "") })
	return client, server
}

func TestPeerAckFrequencyNegotiatedRealConnection(t *testing.T) {
	for _, mode := range []string{"enabled", "peer-disabled", "sender-disabled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			trace := &legacyAckFrequencyTrace{frames: make(chan *wire.LegacyAckFrequencyFrame, 16)}
			serverConfig := &Config{LegacyAckFrequencyMinDelay: time.Millisecond,
				Tracer: func(context.Context, bool, ConnectionID) qlogwriter.Trace { return trace }}
			if mode == "peer-disabled" {
				serverConfig.LegacyAckFrequencyMinDelay = 0
			}
			var calls atomic.Int32
			infos := make(chan PeerAckFrequencyInfo, 1)
			policy := PeerAckFrequencyPolicy(func(info PeerAckFrequencyInfo) (PeerAckFrequency, bool) {
				calls.Add(1)
				select {
				case infos <- info:
				default:
				}
				target := PeerAckFrequency{AckElicitingThreshold: 5, MaxAckDelay: 2 * time.Millisecond}
				return target, info.Current != target
			})
			if mode == "sender-disabled" {
				policy = nil
			}
			client, server := peerAckFrequencyConnectionPair(t, ctx, serverConfig,
				&Config{ClientHandshake: &ClientHandshake{PeerAckFrequencyPolicy: policy}})
			if mode == "enabled" {
				select {
				case frame := <-trace.frames:
					require.EqualValues(t, 0, frame.SequenceNumber)
					require.EqualValues(t, 5, frame.AckElicitingThreshold)
					require.Equal(t, 2*time.Millisecond, frame.RequestMaxAckDelay)
					require.False(t, frame.IgnoreOrder)
				case <-ctx.Done():
					t.Fatal(context.Cause(ctx))
				}
				info := <-infos
				require.Equal(t, time.Millisecond, info.PeerMinAckDelay)
				require.Positive(t, info.CongestionWindow)
				require.GreaterOrEqual(t, info.MaxDatagramSize, uint64(1200))
				require.Positive(t, info.SmoothedRTT)
			}
			stream, err := client.OpenUniStream()
			require.NoError(t, err)
			_, err = stream.Write([]byte("usable after ACK frequency negotiation"))
			require.NoError(t, err)
			require.NoError(t, stream.Close())
			incoming, err := server.AcceptUniStream(ctx)
			require.NoError(t, err)
			deadline, _ := ctx.Deadline()
			incoming.SetReadDeadline(deadline)
			body, err := io.ReadAll(incoming)
			require.NoError(t, err)
			require.Equal(t, "usable after ACK frequency negotiation", string(body))
			if mode != "enabled" {
				require.Zero(t, calls.Load(), "callback must not run without both opt-in and peer support")
				select {
				case frame := <-trace.frames:
					t.Fatalf("unexpected frame: %+v", frame)
				default:
				}
			}
		})
	}
}

func TestLegacyAckFrequencyCommonConfigValidation(t *testing.T) {
	for _, delay := range []time.Duration{-time.Millisecond, time.Nanosecond, 26 * time.Millisecond} {
		err := validateConfig(&Config{LegacyAckFrequencyMinDelay: delay})
		require.Error(t, err)
	}
	config := &Config{LegacyAckFrequencyMinDelay: time.Millisecond}
	cloned := populateConfig(config.Clone())
	require.Equal(t, time.Millisecond, cloned.LegacyAckFrequencyMinDelay)
	for _, packets := range []uint32{1, 10001} {
		require.Error(t, (&ClientHandshake{InitialCongestionWindowPackets: packets}).Validate())
	}
	for _, packets := range []uint32{0, 2, 10, 10000} {
		h := &ClientHandshake{InitialCongestionWindowPackets: packets}
		require.NoError(t, h.Validate())
		require.Equal(t, packets, h.Clone().InitialCongestionWindowPackets)
	}
}

func TestPeerAckFrequencyInvalidPolicyClosesEstablishedConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var invalid atomic.Bool
	client, _ := peerAckFrequencyConnectionPair(t, ctx,
		&Config{LegacyAckFrequencyMinDelay: time.Millisecond},
		&Config{ClientHandshake: &ClientHandshake{PeerAckFrequencyPolicy: func(info PeerAckFrequencyInfo) (PeerAckFrequency, bool) {
			if invalid.Load() {
				return PeerAckFrequency{}, true
			}
			target := PeerAckFrequency{AckElicitingThreshold: 2, MaxAckDelay: time.Millisecond}
			return target, target != info.Current
		}}})
	stream, err := client.OpenUniStream()
	require.NoError(t, err)
	invalid.Store(true)
	stream.Write([]byte("trigger a policy update after the handshake"))
	stream.Close()
	select {
	case <-client.Context().Done():
		require.ErrorContains(t, context.Cause(client.Context()), "policy result")
	case <-ctx.Done():
		t.Fatal(context.Cause(ctx))
	}
}
