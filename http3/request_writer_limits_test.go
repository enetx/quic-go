package http3

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func TestRequestFieldSectionLimitBeforeEncoding(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT"} {
		for _, split := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/split=%t", method, split), func(t *testing.T) {
				req, err := http.NewRequest(method, "https://example.com/path", strings.NewReader("body"))
				require.NoError(t, err)
				req.Header = http.Header{"Cookie": {"a=1; b=2"}, "X-Last": {"value"}, "Header-Order:": {"cookie", "x-last"}}
				original := req.Header.Clone()
				baseline := newRequestWriter()
				baseline.qpackConfig = &QPACKConfig{SplitCookies: split}
				var encoded bytes.Buffer
				require.NoError(t, baseline.WriteRequestHeader(&encoded, req, false, 0, nil))
				reader := bytes.NewReader(encoded.Bytes())
				frame, err := (&frameParser{r: reader}).ParseNext(nil)
				require.NoError(t, err)
				require.IsType(t, &headersFrame{}, frame)
				fields := decodeStaticQPACK(t, encoded.Bytes()[len(encoded.Bytes())-reader.Len():])
				var size int64
				for _, field := range fields {
					size += int64(32 + len(field.Name) + len(field.Value))
				}
				writer := newRequestWriter()
				writer.qpackConfig = baseline.qpackConfig
				limit := size - 1
				writer.peerMaxFieldSectionSize = func() int64 { return limit }
				calls := 0
				writer.encodeQPACK = func(quic.StreamID, []base.HeaderField) ([]byte, error) { calls++; return []byte{0, 0}, nil }
				for _, value := range []int64{size - 1, 0} {
					limit = value
					var output bytes.Buffer
					err := writer.WriteRequestHeader(&output, req, false, 0, nil)
					require.ErrorContains(t, err, "exceeds peer limit")
					require.Zero(t, calls, "rejected fields must not mutate dynamic state")
					require.Zero(t, output.Len())
				}
				for _, value := range []int64{size, -1} {
					limit = value
					require.NoError(t, writer.WriteRequestHeader(&bytes.Buffer{}, req, false, 4, nil))
				}
				require.Equal(t, 2, calls)
				require.Equal(t, original, req.Header)
			})
		}
	}
}

func TestRequestTrailerFieldSectionLimit(t *testing.T) {
	for _, dynamic := range []bool{false, true} {
		t.Run(fmt.Sprint(dynamic), func(t *testing.T) {
			req, err := http.NewRequest("POST", "https://example.com/", nil)
			require.NoError(t, err)
			req.Trailer = http.Header{"X-A": {"one", "two"}, "Content-Length": {"ignored"}, "Header-Order:": {"x-a"}}
			writer := newRequestWriter()
			limit := int64(2 * (32 + len("x-a") + len("one")))
			writer.peerMaxFieldSectionSize = func() int64 { return limit }
			calls := 0
			if dynamic {
				writer.encodeQPACK = func(quic.StreamID, []base.HeaderField) ([]byte, error) { calls++; return []byte{0, 0}, nil }
			}
			var output bytes.Buffer
			require.NoError(t, writer.WriteRequestTrailer(&output, req, 0, nil))
			require.NotZero(t, output.Len())
			output.Reset()
			before := calls
			limit--
			require.ErrorContains(t, writer.WriteRequestTrailer(&output, req, 0, nil), "exceeds peer limit")
			require.Zero(t, output.Len())
			require.Equal(t, before, calls)
		})
	}
}
