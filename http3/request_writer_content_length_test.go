package http3

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/enetx/http"
	httpcommon "github.com/enetx/http/headerorder"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3/qlog"
	"github.com/enetx/quic-go/testutils/events"
	"github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func regularRequestFields(fields []qpack.HeaderField) []qpack.HeaderField {
	var regular []qpack.HeaderField
	for _, field := range fields {
		if !strings.HasPrefix(field.Name, ":") {
			regular = append(regular, field)
		}
	}
	return regular
}

func TestRequestWriterOrderedContentLengthOnWire(t *testing.T) {
	for _, connectionEncoder := range []bool{false, true} {
		name := "static encoder"
		if connectionEncoder {
			name = "connection encoder"
		}
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name  string
				order []string
				slot  int
			}{
				{name: "first", order: []string{"content-length", "x-before", "cookie", "sec-ch-ua-arch", "sec-ch-ua-full-version-list", "x-after"}, slot: 0},
				{name: "between cookies and hints", order: []string{"x-before", "cookie", "content-length", "sec-ch-ua-arch", "sec-ch-ua-full-version-list", "x-after"}, slot: 4},
				{name: "last", order: []string{"x-before", "cookie", "sec-ch-ua-arch", "sec-ch-ua-full-version-list", "x-after", "content-length"}, slot: 7},
				{name: "case insensitive", order: []string{"x-before", "cookie", "CONTENT-LENGTH", "sec-ch-ua-arch", "sec-ch-ua-full-version-list", "x-after"}, slot: 4},
				{name: "last duplicate position wins", order: []string{"content-length", "x-before", "cookie", "CONTENT-LENGTH", "sec-ch-ua-arch", "sec-ch-ua-full-version-list", "x-after"}, slot: 4},
			} {
				t.Run(tc.name, func(t *testing.T) {
					req, err := http.NewRequest(http.MethodPost, "https://example.com/upload", strings.NewReader("payload"))
					require.NoError(t, err)
					req.Header = http.Header{
						"X-Before":                    {"before"},
						"X-After":                     {"after"},
						"Cookie":                      {"first=1; second=2", "third=3"},
						"Sec-Ch-Ua-Arch":              {`"x86"`},
						"Sec-Ch-Ua-Full-Version-List": {`"Product";v="1"`},
						"User-Agent":                  nil,
						"Content-Length":              {"999", "not a length"},
						"content-length":              {"123"},
						"CoNtEnT-LeNgTh":              {"456"},
						httpcommon.HeaderOrderKey:     slices.Clone(tc.order),
						httpcommon.PHeaderOrderKey:    {":method", ":scheme", ":authority", ":path"},
						httpcommon.HeaderCaseKey:      {"sec-ch-ua-arch"},
					}
					original := req.Header.Clone()
					w := newRequestWriter()
					w.qpackConfig = &QPACKConfig{SplitCookies: true}
					var collected []qpack.HeaderField
					if connectionEncoder {
						w.encodeQPACK = func(_ quic.StreamID, fields []qpack.HeaderField) ([]byte, error) {
							collected = slices.Clone(fields)
							var block bytes.Buffer
							encoder := qpack.NewEncoder(&block)
							for _, field := range fields {
								if err := encoder.WriteField(field); err != nil {
									return nil, err
								}
							}
							if err := encoder.Close(); err != nil {
								return nil, err
							}
							return block.Bytes(), nil
						}
					}
					var recorder events.Recorder
					fields := forkWireHeaders(t, w, req, &recorder)
					want := []qpack.HeaderField{
						{Name: "x-before", Value: "before"},
						{Name: "cookie", Value: "first=1"},
						{Name: "cookie", Value: "second=2"},
						{Name: "cookie", Value: "third=3"},
						{Name: "sec-ch-ua-arch", Value: `"x86"`},
						{Name: "sec-ch-ua-full-version-list", Value: `"Product";v="1"`},
						{Name: "x-after", Value: "after"},
					}
					want = slices.Insert(want, tc.slot, qpack.HeaderField{Name: "content-length", Value: "7"})
					require.Equal(t, want, regularRequestFields(fields))
					require.Equal(t, original, req.Header)
					if connectionEncoder {
						require.Equal(t, fields, collected)
					}
					logged := recorder.Events(qlog.FrameCreated{})
					require.Len(t, logged, 1)
					headers := logged[0].(qlog.FrameCreated).Frame.Frame.(qlog.HeadersFrame).HeaderFields
					require.Len(t, headers, len(fields))
					for i, field := range fields {
						require.Equal(t, qlog.HeaderField{Name: field.Name, Value: field.Value}, headers[i])
					}
				})
			}
		})
	}
}

func TestRequestWriterContentLengthRulesOnWire(t *testing.T) {
	// Reuse one writer across requests with different methods, lengths and orders.
	// Computed fields and metadata must not survive into the next request.
	w := newRequestWriter()
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			for _, body := range []struct {
				name   string
				new    func() io.ReadCloser
				length int64
				want   string
			}{
				{name: "nil body", length: 0, want: "0"},
				{name: "nil body ignores stale length", length: 23, want: "0"},
				{name: "NoBody ignores stale length", new: func() io.ReadCloser { return http.NoBody }, length: 23, want: "0"},
				{name: "known stream", new: func() io.ReadCloser { return io.NopCloser(strings.NewReader("payload")) }, length: 7, want: "7"},
				{name: "unknown zero length stream", new: func() io.ReadCloser { return io.NopCloser(strings.NewReader("payload")) }, length: 0},
				{name: "unknown negative length stream", new: func() io.ReadCloser { return io.NopCloser(strings.NewReader("payload")) }, length: -1},
			} {
				t.Run(body.name, func(t *testing.T) {
					for _, order := range []struct {
						name  string
						names []string
						want  []qpack.HeaderField
						slot  int
					}{
						{name: "no order", want: []qpack.HeaderField{{Name: "x-after", Value: "after"}, {Name: "x-before", Value: "before"}}, slot: 2},
						{name: "empty order", names: []string{}, want: []qpack.HeaderField{{Name: "x-after", Value: "after"}, {Name: "x-before", Value: "before"}}, slot: 2},
						{name: "unlisted length", names: []string{"x-before", "x-after"}, want: []qpack.HeaderField{{Name: "x-before", Value: "before"}, {Name: "x-after", Value: "after"}}, slot: 2},
						{name: "ordered length", names: []string{"x-before", "content-length", "x-after"}, want: []qpack.HeaderField{{Name: "x-before", Value: "before"}, {Name: "x-after", Value: "after"}}, slot: 1},
					} {
						t.Run(order.name, func(t *testing.T) {
							req, err := http.NewRequest(method, "https://example.com/upload", nil)
							require.NoError(t, err)
							if body.new != nil {
								req.Body = body.new()
								defer req.Body.Close()
							}
							req.ContentLength = body.length
							req.Header = http.Header{
								"X-Before":       {"before"},
								"X-After":        {"after"},
								"User-Agent":     nil,
								"Content-Length": {"999", "not a length"},
								"content-length": {"123"},
							}
							if order.names != nil {
								req.Header[httpcommon.HeaderOrderKey] = slices.Clone(order.names)
							}
							original := req.Header.Clone()
							fields := forkWireHeaders(t, w, req, nil)
							wantLength := body.want
							if wantLength == "0" && (method == http.MethodGet || method == http.MethodHead) {
								wantLength = ""
							}
							want := slices.Clone(order.want)
							if wantLength != "" {
								want = slices.Insert(want, order.slot, qpack.HeaderField{Name: "content-length", Value: wantLength})
							}
							require.Equal(t, want, regularRequestFields(fields))
							require.Equal(t, original, req.Header)
							require.Equal(t, body.length, req.ContentLength)
							if req.Body != nil {
								data, err := io.ReadAll(req.Body)
								require.NoError(t, err)
								if req.Body == http.NoBody {
									require.Empty(t, data)
								} else {
									require.Equal(t, "payload", string(data), "encoding headers must not consume the body")
								}
							}
						})
					}
				})
			}
		})
	}
}

func TestRequestWriterContentLengthKeepsOtherImplicitFieldOrder(t *testing.T) {
	for _, ordered := range []bool{false, true} {
		name := "upstream default"
		if ordered {
			name = "explicit length slot"
		}
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "https://example.com/upload", strings.NewReader("payload"))
			require.NoError(t, err)
			req.Header.Set("X-Test", "value")
			want := []qpack.HeaderField{
				{Name: "x-test", Value: "value"},
				{Name: "content-length", Value: "7"},
				{Name: "accept-encoding", Value: "gzip"},
				{Name: "user-agent", Value: defaultUserAgent},
			}
			if ordered {
				req.Header[httpcommon.HeaderOrderKey] = []string{"content-length", "x-test"}
				want[0], want[1] = want[1], want[0]
			}
			original := req.Header.Clone()
			var wire bytes.Buffer
			require.NoError(t, newRequestWriter().WriteRequestHeader(&wire, req, true, 0, nil))
			frame, err := (&frameParser{r: &wire}).ParseNext(nil)
			require.NoError(t, err)
			require.IsType(t, &headersFrame{}, frame)
			block := make([]byte, frame.(*headersFrame).Length)
			_, err = io.ReadFull(&wire, block)
			require.NoError(t, err)
			require.Zero(t, wire.Len())
			require.Equal(t, want, regularRequestFields(decodeQpackHeaderFields(t, block)))
			require.Equal(t, original, req.Header)
		})
	}
}

func TestRequestWriterOrderedContentLengthPreservesValidation(t *testing.T) {
	for _, tc := range []struct{ name, key, value string }{
		{name: "newline in canonical value", key: "Content-Length", value: "7\r\nX-Injected: yes"},
		{name: "NUL in case alias", key: "cOnTeNt-LeNgTh", value: "7\x00"},
		{name: "invalid ordinary name", key: "Bad:Name", value: "value"},
		{name: "invalid ordinary value", key: "X-Invalid", value: "bad\nvalue"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "https://example.com/upload", strings.NewReader("payload"))
			require.NoError(t, err)
			req.Header[httpcommon.HeaderOrderKey] = []string{"x-before", "content-length", "x-after"}
			req.Header[tc.key] = []string{tc.value}
			original := req.Header.Clone()
			w := newRequestWriter()
			var wire bytes.Buffer
			require.ErrorContains(t, w.WriteRequestHeader(&wire, req, false, 0, nil), "invalid HTTP header")
			require.Zero(t, wire.Len(), "invalid headers must not write a HEADERS frame")
			require.Equal(t, original, req.Header)

			valid := req.Clone(req.Context())
			delete(valid.Header, tc.key)
			valid.Header.Set("X-Before", "before")
			valid.Header.Set("X-After", "after")
			valid.Header["User-Agent"] = nil
			fields := forkWireHeaders(t, w, valid, nil)
			require.Equal(t, []qpack.HeaderField{
				{Name: "x-before", Value: "before"},
				{Name: "content-length", Value: "7"},
				{Name: "x-after", Value: "after"},
			}, regularRequestFields(fields), "an invalid request must leave the encoder reusable")
			require.Equal(t, original, req.Header)
		})
	}
}
