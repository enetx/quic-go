package quic

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/qerr"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/quic-go/transportparams"
	"github.com/stretchr/testify/require"
)

type legacyAckFrequencyTrace struct {
	frames chan *wire.LegacyAckFrequencyFrame
}

func (t *legacyAckFrequencyTrace) AddProducer() qlogwriter.Recorder { return t }
func (t *legacyAckFrequencyTrace) Close() error                     { return nil }
func (t *legacyAckFrequencyTrace) RecordEvent(event qlogwriter.Event) {
	if packet, ok := event.(qlog.PacketReceived); ok {
		for _, f := range packet.Frames {
			if frame, ok := f.Frame.(*wire.LegacyAckFrequencyFrame); ok {
				select {
				case t.frames <- frame:
				default:
				}
			}
		}
	}
}

func TestLegacyAckFrequencyRealConnection(t *testing.T) {
	for _, name := range []string{"enabled", "disabled", "delay-below-minimum"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			serverTLS := testdata.GetTLSConfig()
			serverTLS.NextProtos = []string{"ack-frequency-test"}
			serverUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer serverUDP.Close()
			serverTransport := &Transport{Conn: serverUDP}
			defer serverTransport.Close()
			listener, err := serverTransport.Listen(serverTLS, nil)
			require.NoError(t, err)
			defer listener.Close()
			trace := &legacyAckFrequencyTrace{frames: make(chan *wire.LegacyAckFrequencyFrame, 4)}
			config := &Config{Tracer: func(context.Context, bool, ConnectionID) qlogwriter.Trace { return trace }}
			if name != "disabled" {
				config.ClientHandshake = &ClientHandshake{LegacyAckFrequencyMinDelay: time.Millisecond}
			}
			clientUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer clientUDP.Close()
			clientTransport := &Transport{Conn: clientUDP}
			defer clientTransport.Close()
			client, err := clientTransport.Dial(ctx, listener.Addr(), &tls.Config{ServerName: "localhost", RootCAs: testdata.GetRootCA(), NextProtos: serverTLS.NextProtos}, config)
			require.NoError(t, err)
			defer client.CloseWithError(0, "")
			server, err := listener.Accept(ctx)
			require.NoError(t, err)
			defer server.CloseWithError(0, "")
			frame := &wire.LegacyAckFrequencyFrame{AckElicitingThreshold: 8, RequestMaxAckDelay: 5 * time.Millisecond, IgnoreOrder: true}
			if name == "delay-below-minimum" {
				frame.RequestMaxAckDelay = time.Microsecond
			}
			server.queueControlFrame(frame)
			if name != "enabled" {
				select {
				case <-client.Context().Done():
				case <-ctx.Done():
					t.Fatal(context.Cause(ctx))
				}
				var transportError *qerr.TransportError
				require.ErrorAs(t, context.Cause(client.Context()), &transportError)
				code := qerr.ProtocolViolation
				if name == "disabled" {
					code = qerr.FrameEncodingError
				}
				require.Equal(t, code, transportError.ErrorCode)
				return
			}
			select {
			case got := <-trace.frames:
				require.Equal(t, frame, got)
			case <-ctx.Done():
				t.Fatal(context.Cause(ctx))
			}
			stream, err := server.OpenUniStream()
			require.NoError(t, err)
			_, err = stream.Write([]byte("live after negotiated update"))
			require.NoError(t, err)
			require.NoError(t, stream.Close())
			incoming, err := client.AcceptUniStream(ctx)
			require.NoError(t, err)
			deadline, _ := ctx.Deadline()
			incoming.SetReadDeadline(deadline)
			body, err := io.ReadAll(incoming)
			require.NoError(t, err)
			require.Equal(t, "live after negotiated update", string(body))
		})
	}
}

func TestLegacyAckFrequencyConfigurationAndAdvertisement(t *testing.T) {
	for _, minimum := range []time.Duration{-time.Millisecond, time.Nanosecond, 26 * time.Millisecond} {
		require.Error(t, (&ClientHandshake{LegacyAckFrequencyMinDelay: minimum}).Validate())
	}
	require.NoError(t, (&ClientHandshake{LegacyAckFrequencyMinDelay: time.Millisecond}).Validate())
	parameters := &wire.TransportParameters{LegacyMinAckDelay: new(time.Millisecond)}
	parameters.ClientLayout = &transportparams.Layout{DisableGrease: true, Order: []uint64{15, 0xff02de1a}}
	encoded := parameters.Marshal(protocol.PerspectiveClient)
	// Check the actual parameter, retained even with DisableGrease enabled.
	require.Contains(t, string(encoded), string([]byte{0xc0, 0x00, 0x00, 0x00, 0xff, 0x02, 0xde, 0x1a, 2, 0x43, 0xe8}))
}
