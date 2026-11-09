package http3_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

type qpackStartupPair struct {
	ctx            context.Context
	client, server *quic.Conn
	h3             *http3.ClientConn
	streams        chan qpackStartupStream
}

func newQPACKStartupPair(t *testing.T, config *http3.QPACKConfig, serverConfig *quic.Config) *qpackStartupPair {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	tlsConfig := testdata.GetTLSConfig()
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, serverConfig)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	client, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3},
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { client.CloseWithError(0, "") })
	server, err := listener.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { server.CloseWithError(0, "") })
	settings := g.NewMapOrd[uint64, uint64]()
	settings.Insert(1, 256)
	settings.Insert(7, 4)
	tr := &http3.Transport{AdditionalSettings: settings, QPACKConfig: config}
	return &qpackStartupPair{ctx: ctx, client: client, server: server, h3: tr.NewClientConn(client), streams: make(chan qpackStartupStream, 4)}
}

func (p *qpackStartupPair) sendHeaders(t *testing.T) {
	t.Helper()
	stream, err := p.h3.OpenRequestStream(p.ctx)
	require.NoError(t, err)
	request, err := http.NewRequestWithContext(p.ctx, http.MethodGet, "https://localhost/", nil)
	require.NoError(t, err)
	require.NoError(t, stream.SendRequestHeader(request))
	require.NoError(t, stream.Close())
	remote, err := p.server.AcceptStream(p.ctx)
	require.NoError(t, err)
	deadline, _ := p.ctx.Deadline()
	remote.SetReadDeadline(deadline)
	r := quicvarint.NewReader(remote)
	kind, err := quicvarint.Read(r)
	require.NoError(t, err)
	require.EqualValues(t, 1, kind)
	length, err := quicvarint.Read(r)
	require.NoError(t, err)
	require.Less(t, length, uint64(4096))
	block := make([]byte, length)
	_, err = io.ReadFull(remote, block)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(block), 2)
	require.Equal(t, []byte{0, 0}, block[:2], "capacity announcements must not create dynamic field references")
}

func (p *qpackStartupPair) readControl(t *testing.T) {
	t.Helper()
	stream, err := p.server.AcceptUniStream(p.ctx)
	require.NoError(t, err)
	deadline, _ := p.ctx.Deadline()
	stream.SetReadDeadline(deadline)
	require.EqualValues(t, 2, stream.StreamID())
	r := quicvarint.NewReader(stream)
	typ, err := quicvarint.Read(r)
	require.NoError(t, err)
	require.Zero(t, typ)
	frame, err := quicvarint.Read(r)
	require.NoError(t, err)
	require.EqualValues(t, 4, frame)
	length, err := quicvarint.Read(r)
	require.NoError(t, err)
	_, err = io.CopyN(io.Discard, stream, int64(length))
	require.NoError(t, err)
	// A higher stream ID implicitly opens lower IDs even when they have no
	// bytes. Parse types concurrently so an unused reserved stream cannot hide
	// instructions arriving on the other QPACK stream.
	go func() {
		for {
			stream, err := p.server.AcceptUniStream(p.ctx)
			if err != nil {
				return
			}
			go func() {
				stream.SetReadDeadline(deadline)
				r := bufio.NewReader(stream)
				typ, err := quicvarint.Read(r)
				if err != nil {
					return
				}
				select {
				case p.streams <- qpackStartupStream{stream, r, http3.QPACKStreamType(typ)}:
				case <-p.ctx.Done():
				}
			}()
		}
	}()
}

func (p *qpackStartupPair) settings(t *testing.T, capacity *uint64) {
	t.Helper()
	stream, err := p.server.OpenUniStream()
	require.NoError(t, err)
	_, err = stream.Write([]byte{0})
	require.NoError(t, err)
	var payload []byte
	if capacity != nil {
		payload = quicvarint.Append(quicvarint.Append(nil, 1), *capacity)
	}
	require.NoError(t, writeFrameQPACK(stream, 4, payload))
	select {
	case <-p.h3.ReceivedSettings():
	case <-p.ctx.Done():
		t.Fatal(context.Cause(p.ctx))
	}
}

type qpackStartupStream struct {
	stream *quic.ReceiveStream
	reader *bufio.Reader
	typ    http3.QPACKStreamType
}

func (p *qpackStartupPair) readQPACKStream(t *testing.T) (http3.QPACKStreamType, qpackStartupStream) {
	t.Helper()
	select {
	case stream := <-p.streams:
		return stream.typ, stream
	case <-p.ctx.Done():
		t.Fatal(context.Cause(p.ctx))
		return 0, qpackStartupStream{}
	}
}

func (p *qpackStartupPair) noQPACKStream(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(p.ctx, 25*time.Millisecond)
	defer cancel()
	select {
	case stream := <-p.streams:
		t.Fatalf("unexpected QPACK stream type %d on ID %d", stream.typ, stream.stream.StreamID())
	case <-ctx.Done():
		require.NoError(t, p.ctx.Err())
	}
}

func (s qpackStartupStream) noInstruction(t *testing.T) {
	t.Helper()
	s.stream.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
	_, err := s.reader.ReadByte()
	var timeout net.Error
	require.ErrorAs(t, err, &timeout)
	require.True(t, timeout.Timeout())
	s.stream.SetReadDeadline(time.Time{})
}

func TestQPACKClientScenarios(t *testing.T) {
	for _, order := range [][]http3.QPACKStreamType{
		{http3.QPACKDecoderStream, http3.QPACKEncoderStream},
		{http3.QPACKEncoderStream, http3.QPACKDecoderStream},
	} {
		for _, eager := range []bool{false, true} {
			for _, timing := range []http3.QPACKCapacityTiming{http3.QPACKCapacityOnSettings, http3.QPACKCapacityBeforeHeaders} {
				for _, peerCapacity := range []uint64{0, 1000, 100000} {
					t.Run(fmt.Sprintf("order-%d/eager-%t/timing-%d/peer-%d", order[0], eager, timing, peerCapacity), func(t *testing.T) {
						p := newQPACKStartupPair(t, &http3.QPACKConfig{
							StreamOrder: order, EagerStreamTypes: eager,
							EncoderTableCapacity: 4096, EncoderCapacityTiming: timing,
						}, nil)
						p.sendHeaders(t) // No peer SETTINGS have arrived yet.
						p.readControl(t)
						streams := make(map[http3.QPACKStreamType]qpackStartupStream)
						if eager {
							for range 2 {
								typ, stream := p.readQPACKStream(t)
								require.NotContains(t, streams, typ)
								streams[typ] = stream
								for i, want := range order {
									if want == typ {
										require.EqualValues(t, 6+4*i, stream.stream.StreamID())
									}
								}
							}
							streams[http3.QPACKEncoderStream].noInstruction(t)
						} else {
							p.noQPACKStream(t)
							probe, err := p.client.OpenUniStream()
							require.NoError(t, err)
							require.EqualValues(t, 14, probe.StreamID(), "both stream IDs must already be reserved")
						}
						p.settings(t, &peerCapacity)
						if timing == http3.QPACKCapacityBeforeHeaders {
							if eager {
								streams[http3.QPACKEncoderStream].noInstruction(t)
							} else {
								p.noQPACKStream(t)
							}
						}
						if timing == http3.QPACKCapacityBeforeHeaders || peerCapacity == 0 {
							p.sendHeaders(t)
						}
						if peerCapacity > 0 {
							if !eager {
								typ, stream := p.readQPACKStream(t)
								require.Equal(t, http3.QPACKEncoderStream, typ)
								streams[typ] = stream
								for i, want := range order {
									if want == typ {
										require.EqualValues(t, 6+4*i, stream.stream.StreamID())
									}
								}
							}
							encoder := streams[http3.QPACKEncoderStream]
							first, err := encoder.reader.ReadByte()
							require.NoError(t, err)
							require.EqualValues(t, 0x20, first&0xe0)
							capacity, err := readPrefQPACK(encoder.reader, first, 5)
							require.NoError(t, err)
							require.Equal(t, min(peerCapacity, 4096), capacity)
						}
						if timing == http3.QPACKCapacityOnSettings && peerCapacity > 0 {
							p.sendHeaders(t)
						}
						p.sendHeaders(t)
						if encoder, ok := streams[http3.QPACKEncoderStream]; ok {
							encoder.noInstruction(t) // One capacity instruction per connection.
						} else {
							p.noQPACKStream(t)
						}
					})
				}
			}
		}
	}
}

func TestQPACKClientNoPeerCapacity(t *testing.T) {
	p := newQPACKStartupPair(t, &http3.QPACKConfig{EncoderTableCapacity: 4096}, nil)
	p.sendHeaders(t)
	p.readControl(t)
	p.settings(t, nil)
	p.sendHeaders(t)
	p.noQPACKStream(t)
}

func TestQPACKClientNativeDefaults(t *testing.T) {
	p := newQPACKStartupPair(t, nil, nil)
	p.sendHeaders(t)
	p.readControl(t)
	capacity := uint64(4096)
	p.settings(t, &capacity)
	p.sendHeaders(t)
	p.noQPACKStream(t)
}

func TestQPACKClientConfigSnapshot(t *testing.T) {
	config := &http3.QPACKConfig{
		StreamOrder:      []http3.QPACKStreamType{http3.QPACKDecoderStream, http3.QPACKEncoderStream},
		EagerStreamTypes: true, EncoderTableCapacity: 128,
	}
	p := newQPACKStartupPair(t, config, nil)
	config.StreamOrder[0], config.EncoderTableCapacity = 99, 999
	p.sendHeaders(t)
	p.readControl(t)
	var encoder qpackStartupStream
	for range 2 {
		typ, stream := p.readQPACKStream(t)
		if typ == http3.QPACKDecoderStream {
			require.EqualValues(t, 6, stream.stream.StreamID())
		} else {
			require.Equal(t, http3.QPACKEncoderStream, typ)
			require.EqualValues(t, 10, stream.stream.StreamID())
			encoder = stream
		}
	}
	capacity := uint64(4096)
	p.settings(t, &capacity)
	first, err := encoder.reader.ReadByte()
	require.NoError(t, err)
	got, err := readPrefQPACK(encoder.reader, first, 5)
	require.NoError(t, err)
	require.EqualValues(t, 128, got)
}

func TestQPACKClientLimitedStreamCredit(t *testing.T) {
	p := newQPACKStartupPair(t, &http3.QPACKConfig{
		StreamOrder:      []http3.QPACKStreamType{http3.QPACKEncoderStream, http3.QPACKDecoderStream},
		EagerStreamTypes: true, EncoderTableCapacity: 4096,
	}, &quic.Config{MaxIncomingUniStreams: 1})
	p.sendHeaders(t)
	p.readControl(t)
	capacity := uint64(4096)
	p.settings(t, &capacity)
	p.sendHeaders(t) // QPACK writers wait for credit without blocking HEADERS.
	p.noQPACKStream(t)
}

func TestQPACKClientCriticalStreamStop(t *testing.T) {
	for _, typ := range []http3.QPACKStreamType{http3.QPACKEncoderStream, http3.QPACKDecoderStream} {
		t.Run(fmt.Sprint(typ), func(t *testing.T) {
			p := newQPACKStartupPair(t, &http3.QPACKConfig{StreamOrder: []http3.QPACKStreamType{typ}, EagerStreamTypes: true}, nil)
			p.sendHeaders(t)
			p.readControl(t)
			gotType, stream := p.readQPACKStream(t)
			require.Equal(t, typ, gotType)
			stream.stream.CancelRead(0)
			select {
			case <-p.client.Context().Done():
			case <-p.ctx.Done():
				t.Fatal("STOP_SENDING on critical stream did not close the connection")
			}
			appErr, ok := errors.AsType[*quic.ApplicationError](context.Cause(p.client.Context()))
			require.True(t, ok)
			require.EqualValues(t, http3.ErrCodeClosedCriticalStream, appErr.ErrorCode)
		})
	}
}

func TestQPACKClientConfigValidation(t *testing.T) {
	for _, config := range []*http3.QPACKConfig{
		{StreamOrder: []http3.QPACKStreamType{2, 2}},
		{StreamOrder: []http3.QPACKStreamType{0}},
		{EncoderTableCapacity: 1 << 62},
		{EncoderCapacityTiming: 99},
	} {
		tr := &http3.Transport{QPACKConfig: config}
		req, err := http.NewRequest(http.MethodGet, "https://localhost/", nil)
		require.NoError(t, err)
		_, err = tr.RoundTrip(req)
		require.ErrorContains(t, err, "QPACK")
		tr.Close()
	}
}

func TestConfiguredDynamicQPACKResponsesAndTrailers(t *testing.T) {
	for _, eager := range []bool{false, true} {
		t.Run(fmt.Sprint(eager), func(t *testing.T) {
			testDynamicQPACKResponsesAndTrailers(t, &http3.QPACKConfig{
				StreamOrder:      []http3.QPACKStreamType{http3.QPACKEncoderStream, http3.QPACKDecoderStream},
				EagerStreamTypes: eager,
			})
		})
	}
}
