package http3_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	codec "github.com/enetx/quic-go/internal/qpack"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func dynamicPeerSettings(t *testing.T, p *qpackStartupPair, capacity, blocked uint64) {
	t.Helper()
	stream, err := p.server.OpenUniStream()
	require.NoError(t, err)
	_, err = stream.Write([]byte{0})
	require.NoError(t, err)
	payload := quicvarint.Append(quicvarint.Append(nil, 1), capacity)
	payload = quicvarint.Append(quicvarint.Append(payload, 7), blocked)
	require.NoError(t, writeFrameQPACK(stream, 4, payload))
	select {
	case <-p.h3.ReceivedSettings():
	case <-p.ctx.Done():
		t.Fatal(context.Cause(p.ctx))
	}
}

func TestHTTP3DynamicRequestEncoder(t *testing.T) {
	for _, postBase := range []bool{false, true} {
		for _, capacity := range []uint64{128, 4096} {
			t.Run(fmt.Sprintf("post=%t/capacity=%d", postBase, capacity), func(t *testing.T) {
				config := &http3.QPACKConfig{DynamicTable: true, EncoderTableCapacity: capacity, PostBaseReferences: postBase,
					Huffman: http3.QPACKHuffmanAuto, StreamOrder: []http3.QPACKStreamType{http3.QPACKEncoderStream, http3.QPACKDecoderStream}}
				p := newQPACKStartupPair(t, config, nil)
				p.readControl(t)
				dynamicPeerSettings(t, p, 65536, 2)
				feedbackStream, err := p.server.OpenUniStream()
				require.NoError(t, err)
				_, err = feedbackStream.Write([]byte{3})
				require.NoError(t, err)
				decoder := codec.NewDecoder(65536, 2, func(b []byte) error { _, err := feedbackStream.Write(b); return err })
				defer decoder.Close(context.Canceled)
				done := make(chan error, 1)
				go func() {
					for {
						select {
						case stream := <-p.streams:
							if stream.typ == http3.QPACKEncoderStream {
								done <- decoder.ReadEncoder(stream.reader)
								return
							}
						case <-p.ctx.Done():
							done <- context.Cause(p.ctx)
							return
						}
					}
				}()
				for i := range 24 {
					stream, err := p.h3.OpenRequestStream(p.ctx)
					require.NoError(t, err)
					req, err := http.NewRequestWithContext(p.ctx, "GET", fmt.Sprintf("https://localhost/path/%d", i), nil)
					require.NoError(t, err)
					req.Header["X-First"] = []string{"first", "second"}
					req.Header["Cookie"] = []string{"a=1; b=2"}
					req.Header["X-Last"] = []string{fmt.Sprint(i)}
					req.Header["Header-Order:"] = []string{"x-first", "cookie", "x-last"}
					require.NoError(t, stream.SendRequestHeader(req))
					require.NoError(t, stream.Close())
					remote, err := p.server.AcceptStream(p.ctx)
					require.NoError(t, err)
					kind, block := readWireFrame(t, remote)
					require.EqualValues(t, 1, kind)
					fields, err := decoder.Decode(p.ctx, uint64(remote.StreamID()), block, 1<<20, nil)
					require.NoError(t, err)
					var ordered []string
					for _, field := range fields {
						if field.Name == "x-first" || field.Name == "cookie" || field.Name == "x-last" {
							ordered = append(ordered, field.Name+"="+field.Value)
						}
					}
					require.Equal(t, []string{"x-first=first", "x-first=second", "cookie=a=1; b=2", "x-last=" + fmt.Sprint(i)}, ordered)
					if i == 0 {
						require.NotZero(t, block[0], "peer SETTINGS should enable dynamic references")
					}
					require.NoError(t, writeFrameQPACK(remote, 1, []byte{0, 0, 0xd9}))
					require.NoError(t, remote.Close())
					response, err := stream.ReadResponse()
					require.NoError(t, err)
					require.Equal(t, 200, response.StatusCode)
					_, err = io.Copy(io.Discard, stream)
					require.NoError(t, err)
				}
				require.NoError(t, p.server.CloseWithError(0, "done"))
				select {
				case <-done:
				case <-p.ctx.Done():
					t.Fatal(context.Cause(p.ctx))
				}
			})
		}
	}
}

func TestHTTP3DynamicEncoderRejectsInvalidFeedback(t *testing.T) {
	for _, data := range [][]byte{{0}, {1}, {0x80}} {
		t.Run(fmt.Sprintf("%x", data), func(t *testing.T) {
			p := newQPACKStartupPair(t, &http3.QPACKConfig{DynamicTable: true, EncoderTableCapacity: 4096}, nil)
			p.readControl(t)
			dynamicPeerSettings(t, p, 4096, 1)
			stream, err := p.server.OpenUniStream()
			require.NoError(t, err)
			_, err = stream.Write(append([]byte{3}, data...))
			require.NoError(t, err)
			select {
			case <-p.client.Context().Done():
			case <-p.ctx.Done():
				t.Fatal(context.Cause(p.ctx))
			}
			var app *quic.ApplicationError
			require.ErrorAs(t, context.Cause(p.client.Context()), &app)
			require.EqualValues(t, http3.ErrCodeQPACKDecoderStreamError, app.ErrorCode)
		})
	}
}

func TestHTTP3DynamicEncoderWithoutStreamCredit(t *testing.T) {
	for _, credit := range []int64{1, 2} {
		t.Run(fmt.Sprint(credit), func(t *testing.T) {
			p := newQPACKStartupPair(t, &http3.QPACKConfig{DynamicTable: true, EncoderTableCapacity: 4096,
				StreamOrder: []http3.QPACKStreamType{http3.QPACKDecoderStream, http3.QPACKEncoderStream}}, &quic.Config{MaxIncomingUniStreams: credit})
			p.readControl(t)
			dynamicPeerSettings(t, p, 4096, 4)
			// Control and optionally decoder reservations exhaust credit. The
			// encoder cannot open: requests must not reference unsendable inserts.
			p.sendHeaders(t)
			p.sendHeaders(t)
		})
	}
}

func TestHTTP3DynamicEncoderConcurrentRequests(t *testing.T) {
	for _, capacity := range []uint64{0, 4096} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			packet, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			settings := g.NewMapOrd[uint64, uint64]()
			settings.Insert(1, capacity)
			settings.Insert(7, 4)
			server := &http3.Server{TLSConfig: testdata.GetTLSConfig(), AdditionalSettings: settings,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if _, err := io.Copy(io.Discard, r.Body); err != nil || r.Trailer.Get("X-Checksum") != "ok" {
						t.Errorf("request body/trailers: %v, %v", err, r.Trailer)
						w.WriteHeader(500)
						return
					}
					io.WriteString(w, r.Header.Get("X-Request-ID"))
				})}
			go server.Serve(packet)
			t.Cleanup(func() { server.Close(); packet.Close() })
			transport := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				QPACKConfig: &http3.QPACKConfig{DynamicTable: true, EncoderTableCapacity: 4096}}
			defer transport.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			do := func(id int) error {
				req, err := http.NewRequestWithContext(ctx, "POST", "https://"+packet.LocalAddr().String()+"/", strings.NewReader("body"))
				if err != nil {
					return err
				}
				req.Header.Set("X-Request-ID", fmt.Sprint(id))
				req.Trailer = http.Header{"X-Checksum": []string{"ok"}}
				res, err := transport.RoundTrip(req)
				if err != nil {
					return err
				}
				defer res.Body.Close()
				body, err := io.ReadAll(res.Body)
				if err != nil {
					return err
				}
				if res.StatusCode != 200 || string(body) != fmt.Sprint(id) {
					return fmt.Errorf("response %d: status %d, body %q", id, res.StatusCode, body)
				}
				return nil
			}
			require.NoError(t, do(-1)) // Complete SETTINGS before concurrent requests.
			results := make(chan error, 32)
			var wg sync.WaitGroup
			for i := range 32 {
				wg.Go(func() { results <- do(i) })
			}
			wg.Wait()
			close(results)
			for err := range results {
				require.NoError(t, err)
			}
		})
	}
}
