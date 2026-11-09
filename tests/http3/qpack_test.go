package http3_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/enetx/quic-go/quicvarint"
	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

type qpackFeedback struct {
	kind  string
	value uint64
}

func prefQPACK(prefix byte, flags byte, value uint64) []byte {
	mask := uint64(1<<prefix) - 1
	if value < mask {
		return []byte{flags | byte(value)}
	}
	b := []byte{flags | byte(mask)}
	value -= mask
	for value >= 128 {
		b = append(b, byte(value&127)|128)
		value >>= 7
	}
	return append(b, byte(value))
}
func readPrefQPACK(reader io.ByteReader, first byte, prefix byte) (uint64, error) {
	mask := uint64(1<<prefix) - 1
	value := uint64(first) & mask
	if value < mask {
		return value, nil
	}
	for shift := uint(0); shift < 63; shift += 7 {
		b, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		value += uint64(b&127) << shift
		if b < 128 {
			return value, nil
		}
	}
	return 0, fmt.Errorf("overflow")
}
func insertQPACK(name, value string) []byte {
	b := prefQPACK(5, 0x40, uint64(len(name)))
	b = append(b, name...)
	b = append(b, prefQPACK(7, 0, uint64(len(value)))...)
	return append(b, value...)
}
func writeFrameQPACK(stream io.Writer, kind uint64, payload []byte) error {
	b := quicvarint.Append(nil, kind)
	b = quicvarint.Append(b, uint64(len(payload)))
	b = append(b, payload...)
	_, err := stream.Write(b)
	return err
}
func collectFeedback(ctx context.Context, conn *quic.Conn, events chan<- qpackFeedback) {
	for {
		stream, err := conn.AcceptUniStream(ctx)
		if err != nil {
			return
		}
		go func() {
			reader := quicvarint.NewReader(stream)
			kind, err := quicvarint.Read(reader)
			if err != nil {
				return
			}
			if kind != 3 {
				io.Copy(io.Discard, stream)
				return
			}
			for {
				first, err := reader.ReadByte()
				if err != nil {
					return
				}
				prefix := byte(6)
				kind := "increment"
				if first&0x80 != 0 {
					prefix = 7
					kind = "ack"
				} else if first&0x40 != 0 {
					kind = "cancel"
				}
				value, err := readPrefQPACK(reader, first, prefix)
				if err != nil {
					return
				}
				select {
				case events <- qpackFeedback{kind, value}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
}
func qpackRawPeer(t *testing.T, serve func(context.Context, *quic.Conn, chan<- qpackFeedback) error) (string, <-chan qpackFeedback) {
	t.Helper()
	tlsConfig := testdata.GetTLSConfig()
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, &quic.Config{})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan qpackFeedback, 256)
	t.Cleanup(func() { cancel(); listener.Close() })
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "")
		control, err := conn.OpenUniStream()
		if err != nil {
			return
		}
		_, err = control.Write([]byte{0, 4, 0})
		if err != nil {
			return
		}
		go collectFeedback(ctx, conn, events)
		if err := serve(ctx, conn, events); err != nil && ctx.Err() == nil {
			t.Errorf("raw QPACK peer: %v", err)
		}
		<-ctx.Done()
	}()
	return "https://" + listener.Addr().String(), events
}
func qpackTransport(t *testing.T, capacity, blocked uint64, limit int) *http3.Transport {
	t.Helper()
	settings := g.NewMapOrd[uint64, uint64]()
	settings.Insert(1, capacity)
	settings.Insert(7, blocked)
	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, AdditionalSettings: settings, MaxResponseHeaderBytes: limit}
	t.Cleanup(func() { tr.Close() })
	return tr
}
func openEncoderQPACK(conn *quic.Conn) (*quic.SendStream, error) {
	stream, err := conn.OpenUniStream()
	if err != nil {
		return nil, err
	}
	_, err = stream.Write([]byte{2})
	return stream, err
}
func requestQPACK(t *testing.T, tr *http3.Transport, url string) (*http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	return tr.RoundTrip(req)
}
func TestDynamicQPACKResponsesAndTrailers(t *testing.T) {
	testDynamicQPACKResponsesAndTrailers(t, nil)
}

func testDynamicQPACKResponsesAndTrailers(t *testing.T, config *http3.QPACKConfig) {
	var connections atomic.Int32
	url, feedback := qpackRawPeer(t, func(ctx context.Context, conn *quic.Conn, _ chan<- qpackFeedback) error {
		connections.Add(1)
		encoder, err := openEncoderQPACK(conn)
		if err != nil {
			return err
		}
		if _, err = encoder.Write(prefQPACK(5, 0x20, 256)); err != nil {
			return err
		}
		for i := 0; i < 2; i++ {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				return err
			}
			// Send a field section before its encoder instructions. The decoder must
			// tolerate delivery in either stream order without corrupting the table.
			if err = writeFrameQPACK(stream, 1, []byte{2, 0, 0xd8, 0x80}); err != nil {
				return err
			} // 103 + dynamic field
			if i == 0 {
				if _, err = encoder.Write(insertQPACK("x-shared", "one")); err != nil {
					return err
				}
			}
			if err = writeFrameQPACK(stream, 1, []byte{2, 0, 0xd9, 0x80}); err != nil {
				return err
			}
			if err = writeFrameQPACK(stream, 0, []byte("ok")); err != nil {
				return err
			}
			if err = writeFrameQPACK(stream, 1, []byte{2, 0, 0x40, 5, 't', 'r', 'a', 'i', 'l'}); err != nil {
				return err
			}
			if err = stream.Close(); err != nil {
				return err
			}
		}
		return nil
	})
	tr := qpackTransport(t, 256, 4, 4096)
	tr.QPACKConfig = config
	for i := 0; i < 2; i++ {
		response, err := requestQPACK(t, tr, url)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		response.Body.Close()
		require.Equal(t, "ok", string(body))
		require.Equal(t, "one", response.Header.Get("X-Shared"))
		require.Equal(t, "trail", response.Trailer.Get("X-Shared"))
	}
	require.EqualValues(t, 1, connections.Load())
	acks := map[uint64]int{}
	increments := uint64(0)
	for count := 0; count < 6; {
		select {
		case event := <-feedback:
			if event.kind == "ack" {
				acks[event.value]++
				count++
			} else if event.kind == "increment" {
				increments += event.value
			} else {
				t.Fatalf("unexpected feedback: %+v", event)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("missing QPACK section acknowledgments")
		}
	}
	require.Equal(t, map[uint64]int{0: 3, 4: 3}, acks)
	require.EqualValues(t, 1, increments)
}
func TestDynamicQPACKBlockedRequestCancellation(t *testing.T) {
	sent := make(chan struct{})
	url, feedback := qpackRawPeer(t, func(ctx context.Context, conn *quic.Conn, _ chan<- qpackFeedback) error {
		encoder, err := openEncoderQPACK(conn)
		if err != nil {
			return err
		}
		if _, err = encoder.Write(prefQPACK(5, 0x20, 256)); err != nil {
			return err
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		if err = writeFrameQPACK(stream, 1, []byte{2, 0, 0xd9, 0x80}); err != nil {
			return err
		}
		close(sent)
		return nil
	})
	tr := qpackTransport(t, 256, 1, 4096)
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { _, err := tr.RoundTrip(req); done <- err }()
	<-sent
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("blocked QPACK ignored cancellation")
	}
	select {
	case event := <-feedback:
		require.Equal(t, qpackFeedback{"cancel", 0}, event)
	case <-time.After(5 * time.Second):
		t.Fatal("missing QPACK stream cancellation")
	}
}
func TestDynamicQPACKConnectionErrors(t *testing.T) {
	for _, tc := range []struct {
		name        string
		kind        uint64
		data        []byte
		block       []byte
		blocked     uint64
		code        http3.ErrCode
		closeStream bool
	}{
		{name: "capacity", kind: 2, data: prefQPACK(5, 0x20, 257), blocked: 1, code: http3.ErrCodeQPACKEncoderStreamError},
		{name: "decoder-ack", kind: 3, data: []byte{0x80}, blocked: 1, code: http3.ErrCodeQPACKDecoderStreamError},
		{name: "decoder-increment", kind: 3, data: []byte{1}, blocked: 1, code: http3.ErrCodeQPACKDecoderStreamError},
		{name: "critical-close", kind: 2, blocked: 1, closeStream: true, code: http3.ErrCodeClosedCriticalStream},
		{name: "blocking-disabled", kind: 2, block: []byte{2, 0, 0xd9, 0x80}, blocked: 0, code: http3.ErrCodeQPACKDecompressionFailed},
		{name: "bad-index", kind: 2, data: append(prefQPACK(5, 0x20, 256), insertQPACK("x", "v")...), block: []byte{2, 0, 0xd9, 0x81}, blocked: 1, code: http3.ErrCodeQPACKDecompressionFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url, _ := qpackRawPeer(t, func(ctx context.Context, conn *quic.Conn, _ chan<- qpackFeedback) error {
				uni, err := conn.OpenUniStream()
				if err != nil {
					return err
				}
				data := quicvarint.Append(nil, tc.kind)
				data = append(data, tc.data...)
				if _, err = uni.Write(data); err != nil {
					return err
				}
				if tc.closeStream {
					return uni.Close()
				}
				if tc.block != nil {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						return err
					}
					return writeFrameQPACK(stream, 1, tc.block)
				}
				return nil
			})
			tr := qpackTransport(t, 256, tc.blocked, 4096)
			response, err := requestQPACK(t, tr, url)
			if response != nil {
				response.Body.Close()
			}
			require.Error(t, err)
			if tc.code == http3.ErrCodeQPACKDecompressionFailed {
				require.ErrorContains(t, err, "QPACK decompression failed")
			} else {
				var application *quic.ApplicationError
				require.True(t, errors.As(err, &application), "%v", err)
				require.EqualValues(t, tc.code, application.ErrorCode)
			}
		})
	}
}
func TestDynamicQPACKHeaderLimit(t *testing.T) {
	url, feedback := qpackRawPeer(t, func(ctx context.Context, conn *quic.Conn, _ chan<- qpackFeedback) error {
		encoder, err := openEncoderQPACK(conn)
		if err != nil {
			return err
		}
		if _, err = encoder.Write(append(prefQPACK(5, 0x20, 256), insertQPACK("x-large", "1234567890")...)); err != nil {
			return err
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		return writeFrameQPACK(stream, 1, []byte{2, 0, 0xd9, 0x80})
	})
	tr := qpackTransport(t, 256, 1, 50)
	_, err := requestQPACK(t, tr, url)
	require.ErrorContains(t, err, "headers too large")
	for {
		select {
		case event := <-feedback:
			if event.kind == "cancel" {
				require.EqualValues(t, 0, event.value)
				return
			}
		case <-time.After(5 * time.Second):
			t.Fatal("header limit did not release QPACK references")
		}
	}
}
func TestServerDynamicQPACKRequest(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	settings := g.NewMapOrd[uint64, uint64]()
	settings.Insert(1, 256)
	settings.Insert(7, 1)
	server := &http3.Server{TLSConfig: testdata.GetTLSConfig(), AdditionalSettings: settings, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(r.Host)) })}
	go server.Serve(packet)
	t.Cleanup(func() { server.Close(); packet.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, packet.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}, &quic.Config{})
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	control, err := conn.OpenUniStream()
	require.NoError(t, err)
	_, err = control.Write([]byte{0, 4, 0})
	require.NoError(t, err)
	feedback := make(chan qpackFeedback, 16)
	go collectFeedback(ctx, conn, feedback)
	encoder, err := openEncoderQPACK(conn)
	require.NoError(t, err)
	_, err = encoder.Write(append(prefQPACK(5, 0x20, 256), insertQPACK(":authority", "example.test")...))
	require.NoError(t, err)
	stream, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	require.NoError(t, writeFrameQPACK(stream, 1, []byte{2, 0, 0xd1, 0xd7, 0xc1, 0x80}))
	stream.Close()
	reader := quicvarint.NewReader(stream)
	kind, err := quicvarint.Read(reader)
	require.NoError(t, err)
	require.EqualValues(t, 1, kind)
	n, err := quicvarint.Read(reader)
	require.NoError(t, err)
	block := make([]byte, n)
	_, err = io.ReadFull(reader, block)
	require.NoError(t, err)
	decode := base.NewDecoder().Decode(block)
	field, err := decode()
	require.NoError(t, err)
	require.Equal(t, base.HeaderField{Name: ":status", Value: "200"}, field)
	kind, err = quicvarint.Read(reader)
	require.NoError(t, err)
	require.EqualValues(t, 0, kind)
	n, err = quicvarint.Read(reader)
	require.NoError(t, err)
	body := make([]byte, n)
	_, err = io.ReadFull(reader, body)
	require.NoError(t, err)
	require.True(t, bytes.Equal(body, []byte("example.test")))
	for {
		select {
		case event := <-feedback:
			if event.kind == "ack" {
				require.EqualValues(t, 0, event.value)
				return
			}
		case <-ctx.Done():
			t.Fatal("server did not acknowledge dynamic request")
		}
	}
}
