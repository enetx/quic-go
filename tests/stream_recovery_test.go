package quic_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/stretchr/testify/require"
)

type recoveryDatagram struct {
	number  int64
	target  bool
	advance bool
}

// recoveryWireUDP receives one normal short-header qlog record for each ordinary
// UDP write. Coalesced records are matched by their actual encrypted checksum.
// It never decrypts or modifies a QUIC packet: one original is delayed, its copy
// is discarded, and the unchanged original is then delivered to the peer.
type recoveryWireUDP struct {
	net.PacketConn
	ctx                                  context.Context
	mu                                   sync.Mutex
	normal                               chan recoveryDatagram
	coalesced                            map[qlog.DatagramPayloadChecksum]recoveryDatagram
	armed                                bool
	original                             []byte
	originalNumber                       int64
	copies, dataAfterACK                 int
	originalLost, lossBeforeCopy         bool
	waitForLoss, released                bool
	ptoExpirations                       int
	acked                                bool
	captured, acknowledged, confirmed    chan struct{}
	advanceWritten, ackProgress          chan int64
	capturedOnce, ackOnce, confirmedOnce sync.Once
}

type recoveryWireTrace struct{ *recoveryWireUDP }

func (r *recoveryWireTrace) AddProducer() qlogwriter.Recorder { return r }
func (r *recoveryWireTrace) Close() error                     { return nil }
func (r *recoveryWireUDP) RecordEvent(event qlogwriter.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch e := event.(type) {
	case qlog.PacketLost:
		if int64(e.Header.PacketNumber) == r.originalNumber {
			r.originalLost = true
		}
	case qlog.TimerUpdated:
		if r.armed && e.Type == qlog.TimerEventTypeExpired && e.TimerType == qlog.TimerTypePTO {
			r.ptoExpirations++
		}
	case qlog.PacketSent:
		if e.Header.PacketType != qlog.PacketType1RTT {
			return
		}
		meta := recoveryDatagram{number: int64(e.Header.PacketNumber)}
		for _, f := range e.Frames {
			if stream, ok := f.Frame.(*qlog.StreamFrame); ok && stream.StreamID == 4 {
				meta.target = true
			}
			if _, ok := f.Frame.(*qlog.DatagramFrame); ok {
				meta.advance = true
			}
		}
		if meta.target && r.acked {
			r.dataAfterACK++
		}
		if e.DatagramPayloadChecksum != 0 {
			r.coalesced[e.DatagramPayloadChecksum] = meta
			return
		}
		r.normal <- meta
	case qlog.PacketReceived:
		if e.Header.PacketType != qlog.PacketType1RTT {
			return
		}
		for _, f := range e.Frames {
			switch frame := f.Frame.(type) {
			case *qlog.HandshakeDoneFrame:
				r.confirmedOnce.Do(func() { close(r.confirmed) })
			case *qlog.AckFrame:
				if len(frame.AckRanges) > 0 {
					select {
					case r.ackProgress <- int64(frame.AckRanges[0].Largest):
					default:
					}
				}
				if r.originalNumber < 0 {
					continue
				}
				for _, part := range frame.AckRanges {
					if int64(part.Smallest) <= r.originalNumber && r.originalNumber <= int64(part.Largest) {
						r.acked = true
						r.ackOnce.Do(func() { close(r.acknowledged) })
					}
				}
			}
		}
	}
}

func (r *recoveryWireUDP) WriteTo(data []byte, addr net.Addr) (int, error) {
	if len(data) == 0 || data[0]&0x80 != 0 {
		return r.PacketConn.WriteTo(data, addr)
	}
	checksum := qlog.CalculateDatagramPayloadChecksum(data)
	r.mu.Lock()
	meta, coalesced := r.coalesced[checksum]
	delete(r.coalesced, checksum)
	r.mu.Unlock()
	if !coalesced {
		select {
		case meta = <-r.normal:
		case <-r.ctx.Done():
			return 0, net.ErrClosed
		}
	}
	// Notify the test after this intercepted UDP write even if a co-packetized
	// STREAM copy makes us deliberately discard the DATAGRAM as well.
	if meta.advance {
		defer func() {
			select {
			case r.advanceWritten <- meta.number:
			case <-r.ctx.Done():
			}
		}()
	}
	r.mu.Lock()
	if !r.armed || !meta.target || r.acked {
		r.mu.Unlock()
		return r.PacketConn.WriteTo(data, addr)
	}
	if r.original == nil {
		r.original = append([]byte(nil), data...)
		r.originalNumber = meta.number
		r.capturedOnce.Do(func() { close(r.captured) })
		r.mu.Unlock()
		return len(data), nil
	}
	r.copies++
	original := r.original
	release := !r.released && (!r.waitForLoss || r.originalLost)
	if release {
		r.released = true
		r.lossBeforeCopy = r.originalLost
	}
	r.mu.Unlock()
	if release {
		if _, err := r.PacketConn.WriteTo(original, addr); err != nil {
			return 0, err
		}
	}
	return len(data), nil
}

func TestLateOriginalSTREAMACKOnEncryptedUDP(t *testing.T) {
	for _, separate := range []bool{false, true} {
		for _, trigger := range []string{"pto", "loss"} {
			name := map[bool]string{false: "shared", true: "separate"}[separate] + "/" + trigger
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
				defer cancel()
				tlsServer := testdata.GetTLSConfig()
				tlsServer.NextProtos = []string{"stream-recovery"}
				listener, err := quic.ListenAddr("127.0.0.1:0", tlsServer, &quic.Config{EnableDatagrams: true})
				require.NoError(t, err)
				defer listener.Close()
				serverResult := make(chan error, 1)
				go func() {
					conn, err := listener.Accept(ctx)
					if err != nil {
						serverResult <- err
						return
					}
					defer conn.CloseWithError(0, "")
					for range 2 {
						stream, err := conn.AcceptStream(ctx)
						if err != nil {
							serverResult <- err
							return
						}
						body, err := io.ReadAll(stream)
						if err == nil {
							_, err = stream.Write(body)
						}
						if err == nil {
							err = stream.Close()
						}
						if err != nil {
							serverResult <- err
							return
						}
					}
					// Keep the connection alive while the copied packet is declared lost.
					<-ctx.Done()
					serverResult <- nil
				}()
				socket, err := net.ListenPacket("udp", "127.0.0.1:0")
				require.NoError(t, err)
				defer socket.Close()
				packet := &recoveryWireUDP{PacketConn: socket, ctx: ctx, normal: make(chan recoveryDatagram, 1024), coalesced: make(map[qlog.DatagramPayloadChecksum]recoveryDatagram), originalNumber: -1, captured: make(chan struct{}), acknowledged: make(chan struct{}), confirmed: make(chan struct{}), advanceWritten: make(chan int64, 16), ackProgress: make(chan int64, 1024)}
				// A slow scheduler may let PTO run before packet-threshold loss.
				// The loss scenario must release the original only after real loss,
				// independently of how many earlier PTO copies were discarded.
				packet.waitForLoss = trigger == "loss"
				transport := &quic.Transport{Conn: packet, ConnectionIDLength: 8}
				defer transport.Close()
				config := &quic.Config{EnableDatagrams: true, DisablePathMTUDiscovery: true, ClientHandshake: &quic.ClientHandshake{DisableClientHelloScrambling: true, StreamDataRecovery: true, SeparatePacketNumberSpaces: separate, DisablePacketNumberSkipping: true, ApplicationProbePackets: 1}, Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return &recoveryWireTrace{packet} }}
				client, err := transport.Dial(ctx, listener.Addr(), &tls.Config{ServerName: "localhost", RootCAs: testdata.GetRootCA(), CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: tlsServer.NextProtos}, config)
				require.NoError(t, err)
				defer client.CloseWithError(0, "")
				exchange := func(text string) error {
					stream, err := client.OpenStreamSync(ctx)
					if err != nil {
						return err
					}
					// Stage payload and FIN in one connection turn. A separately
					// packetized new FIN is not a copy of the delayed payload.
					if _, err = client.TryWriteStreamBatch([]quic.StreamWrite{{StreamID: stream.StreamID(), Data: []byte(text), Fin: true}}); err != nil {
						return err
					}
					body, err := io.ReadAll(stream)
					if err == nil && string(body) != text {
						return errors.New("stream body changed")
					}
					return err
				}
				require.NoError(t, exchange("warm"))
				select {
				case <-packet.confirmed:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				require.NotEmpty(t, client.ConnectionState().TLS.VerifiedChains)
				packet.mu.Lock()
				packet.armed = true
				packet.mu.Unlock()
				advance := func(text string) int64 {
					t.Helper()
					require.NoError(t, client.SendDatagram([]byte(text)))
					select {
					case pn := <-packet.advanceWritten:
						return pn
					case <-ctx.Done():
						t.Fatal(ctx.Err())
						return -1
					}
				}
				done := make(chan error, 1)
				go func() { done <- exchange("the original STREAM must satisfy every copy") }()
				select {
				case <-packet.captured:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if trigger == "loss" {
					// Fresh ack-eliciting packets let the peer acknowledge beyond the delayed
					// original. They induce actual loss before the original finally arrives.
					for range 4 {
						// Wait for an intercepted UDP write, rather than assuming a sleep
						// made each DATAGRAM into a distinct QUIC packet.
						advance("advance ACK")
					}
				}
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				select {
				case <-packet.acknowledged:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				// Advance ACKs beyond the discarded copy, exercising its eventual OnLost.
				var last int64
				for range 6 {
					last = advance("after original ACK")
				}
			ackBarrier:
				for {
					select {
					case pn := <-packet.ackProgress:
						if pn >= last {
							break ackBarrier
						}
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				}
				packet.mu.Lock()
				copies, late := packet.copies, packet.dataAfterACK
				lost, ptos := packet.lossBeforeCopy, packet.ptoExpirations
				packet.mu.Unlock()
				require.Positive(t, copies)
				require.Equal(t, trigger == "loss", lost)
				if trigger == "pto" {
					require.Positive(t, ptos)
				}
				require.Zero(t, late, "already acknowledged STREAM data was sent again")
				cancel()
				require.NoError(t, <-serverResult)
			})
		}
	}
}
