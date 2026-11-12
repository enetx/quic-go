package http3

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func TestRequestWriterContentLengthEmptyBodyOptOut(t *testing.T) {
	for _, connectionEncoder := range []bool{false, true} {
		encoderName := "static encoder"
		if connectionEncoder {
			encoderName = "connection encoder"
		}
		t.Run(encoderName, func(t *testing.T) {
			w := newRequestWriter()
			if connectionEncoder {
				w.encodeQPACK = func(_ quic.StreamID, fields []qpack.HeaderField) ([]byte, error) {
					var block bytes.Buffer
					enc := qpack.NewEncoder(&block)
					for _, field := range fields {
						if err := enc.WriteField(field); err != nil {
							return nil, err
						}
					}
					if err := enc.Close(); err != nil {
						return nil, err
					}
					return block.Bytes(), nil
				}
			}
			for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
				for _, body := range []struct {
					name, data string
					length     int64
					replay     bool
				}{
					{name: "absent"},
					{name: "explicit empty upload", replay: true},
					{name: "known upload", data: "abc", length: 3},
					{name: "unknown upload", data: "abc", length: -1, replay: true},
					{name: "unknown zero field", data: "abc", replay: true},
				} {
					for _, marker := range []struct {
						name, key string
						values    []string
						omit      bool
					}{
						{name: "upstream default"},
						{name: "nil canonical", key: "Content-Length", omit: true},
						{name: "nil mixed case", key: "cOnTeNt-LeNgTh", omit: true},
						{name: "empty slice", key: "content-length", values: []string{}, omit: true},
						{name: "untrusted value", key: "cOnTeNt-LeNgTh", values: []string{"999", "not a length"}},
						{name: "empty string is not nil", key: "Content-Length", values: []string{""}},
					} {
						for _, order := range []string{"none", "unlisted length", "ordered length"} {
							t.Run(method+"/"+body.name+"/"+marker.name+"/"+order, func(t *testing.T) {
								req, err := http.NewRequest(method, "https://example.com/upload", nil)
								require.NoError(t, err)
								reader := strings.NewReader(body.data)
								if body.data != "" {
									req.Body = io.NopCloser(reader)
								}
								req.ContentLength = body.length
								if body.replay {
									req.GetBody = func() (io.ReadCloser, error) { panic("encoding must not call GetBody") }
								}
								req.Header = http.Header{"User-Agent": nil, "X-Before": {"before"}, "X-After": {"after"}}
								if marker.key != "" {
									req.Header[marker.key] = marker.values
								}
								if order != "none" {
									req.Header[http.HeaderOrderKey] = []string{"x-before", "x-after"}
									if order == "ordered length" {
										req.Header[http.HeaderOrderKey] = []string{"x-before", "CONTENT-LENGTH", "x-after"}
									}
								}
								original := req.Header.Clone()
								fields := forkWireHeaders(t, w, req, nil)
								actualLength := body.length
								if body.data != "" && actualLength == 0 {
									actualLength = -1
								}
								want := ""
								if actualLength > 0 {
									want = "3"
								} else if actualLength == 0 && !marker.omit && (method == "POST" || method == "PUT" || method == "PATCH" || body.replay && order == "ordered length") {
									want = "0"
								}
								var lengths []string
								for _, field := range fields {
									if field.Name == "content-length" {
										lengths = append(lengths, field.Value)
									}
								}
								if want == "" {
									require.Empty(t, lengths)
								} else {
									require.Equal(t, []string{want}, lengths)
									if order == "ordered length" {
										require.Equal(t, []qpack.HeaderField{{Name: "x-before", Value: "before"}, {Name: "content-length", Value: want}, {Name: "x-after", Value: "after"}}, regularRequestFields(fields))
									}
								}
								require.Equal(t, len(body.data), reader.Len(), "encoding must not read the body")
								require.Equal(t, original, req.Header)
								require.Equal(t, body.length, req.ContentLength)
							})
						}
					}
				}
			}
		})
	}
}

func TestRequestWriterNilLengthUsesSanitizedBodyLength(t *testing.T) {
	w := newRequestWriter()
	for _, body := range []io.ReadCloser{nil, http.NoBody} {
		req, err := http.NewRequest(http.MethodPatch, "https://example.com/upload", nil)
		require.NoError(t, err)
		req.Body = body
		req.ContentLength = 23
		req.Header["CONTENT-LENGTH"] = nil
		req.Header[http.HeaderOrderKey] = []string{"content-length"}
		original := req.Header.Clone()
		fields := forkWireHeaders(t, w, req, nil)
		require.False(t, slices.ContainsFunc(fields, func(field qpack.HeaderField) bool { return field.Name == "content-length" }))
		require.Equal(t, original, req.Header)
	}
}
