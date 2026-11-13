package self_test

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func sendUncheckedHTTP3Headers(t *testing.T, port int, headers http.Header) int {
	t.Helper()
	tlsConfig := getTLSClientConfig()
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	conn, err := quic.DialAddr(t.Context(), fmt.Sprintf("localhost:%d", port), tlsConfig, getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	control, err := conn.OpenUniStreamSync(t.Context())
	require.NoError(t, err)
	_, err = control.Write([]byte{0, 4, 0})
	require.NoError(t, err)
	var block bytes.Buffer
	encoder := qpack.NewEncoder(&block)
	for _, field := range []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "localhost"}, {Name: ":path", Value: "/headers"}} {
		require.NoError(t, encoder.WriteField(field))
	}
	for name, values := range headers {
		for _, value := range values {
			require.NoError(t, encoder.WriteField(qpack.HeaderField{Name: strings.ToLower(name), Value: value}))
		}
	}
	require.NoError(t, encoder.Close())
	frame := quicvarint.Append(quicvarint.Append(nil, 1), uint64(block.Len()))
	frame = append(frame, block.Bytes()...)
	stream, err := conn.OpenStreamSync(t.Context())
	require.NoError(t, err)
	_, err = stream.Write(frame)
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	require.NoError(t, stream.SetReadDeadline(time.Now().Add(3*time.Second)))
	r := quicvarint.NewReader(stream)
	typ, err := quicvarint.Read(r)
	require.NoError(t, err)
	require.EqualValues(t, 1, typ)
	length, err := quicvarint.Read(r)
	require.NoError(t, err)
	require.Less(t, length, uint64(8192))
	response := make([]byte, length)
	_, err = io.ReadFull(stream, response)
	require.NoError(t, err)
	decode := qpack.NewDecoder().Decode(response)
	status := ""
	for {
		field, err := decode()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if field.Name == ":status" {
			status = field.Value
		}
	}
	require.Equal(t, "431", status)
	return len(frame)
}
