package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net/textproto"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/http/httptrace"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func TestClientResponseHeaderCallbacks(t *testing.T) {
	for _, mode := range []string{"observe", "header-error", "trace-error"} {
		t.Run(mode, func(t *testing.T) {
			client, server := newConnPair(t)
			failure := errors.New("application stopped response")
			var observed, traced []int
			wire := &WireConfig{OnResponseHeaders: func(_ *http.Request, response *http.Response) error {
				observed = append(observed, response.StatusCode)
				if mode == "header-error" {
					return failure
				}
				return nil
			}}
			trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
				traced = append(traced, code)
				if mode == "trace-error" {
					return failure
				}
				return nil
			}}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				conn := (&Transport{WireConfig: wire}).NewClientConn(client)
				request := httptest.NewRequest("GET", "https://example.com", nil).WithContext(httptrace.WithClientTrace(ctx, trace))
				response, err := conn.RoundTrip(request)
				if response != nil {
					response.Body.Close()
				}
				result <- err
			}()
			stream, err := server.AcceptStream(ctx)
			require.NoError(t, err)
			decodeHeader(t, stream)
			var frames []byte
			for _, status := range []string{"103", "200"} {
				var block bytes.Buffer
				require.NoError(t, qpack.NewEncoder(&block).WriteField(qpack.HeaderField{Name: ":status", Value: status}))
				frames = quicvarint.Append(frames, 1)
				frames = quicvarint.Append(frames, uint64(block.Len()))
				frames = append(frames, block.Bytes()...)
			}
			_, err = stream.Write(frames)
			require.NoError(t, err)
			stream.Close()
			select {
			case err := <-result:
				if mode == "observe" {
					require.NoError(t, err)
					require.Equal(t, []int{103, 200}, observed)
				} else {
					require.ErrorIs(t, err, failure)
					require.Equal(t, []int{103}, observed)
				}
				if mode == "header-error" {
					require.Empty(t, traced)
				} else {
					require.Equal(t, []int{103}, traced)
				}
			case <-ctx.Done():
				t.Fatal(context.Cause(ctx))
			}
		})
	}
}

func TestInformationalResponseCommitsAttemptBeforeRequestRejectedReset(t *testing.T) {
	client, server := newConnPair(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	observed := make(chan struct{})
	result := make(chan error, 1)
	dials := 0
	transport := &Transport{Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
		dials++
		if dials > 1 {
			return nil, errors.New("unexpected replay after informational response")
		}
		return client, nil
	}}
	defer transport.Close()
	go func() {
		trace := &httptrace.ClientTrace{Got1xxResponse: func(int, textproto.MIMEHeader) error {
			close(observed)
			return nil
		}}
		request := httptest.NewRequest("GET", "https://example.com", nil).
			WithContext(httptrace.WithClientTrace(ctx, trace))
		_, err := transport.RoundTrip(request)
		result <- err
	}()
	stream, err := server.AcceptStream(ctx)
	require.NoError(t, err)
	decodeHeader(t, stream)
	var block bytes.Buffer
	require.NoError(t, qpack.NewEncoder(&block).WriteField(qpack.HeaderField{Name: ":status", Value: "103"}))
	frames := quicvarint.Append(nil, 1)
	frames = quicvarint.Append(frames, uint64(block.Len()))
	frames = append(frames, block.Bytes()...)
	_, err = stream.Write(frames)
	require.NoError(t, err)
	select {
	case <-observed:
	case <-ctx.Done():
		t.Fatal(context.Cause(ctx))
	}
	stream.CancelWrite(quic.StreamErrorCode(ErrCodeRequestRejected))
	select {
	case err := <-result:
		var received *responseReceivedError
		require.ErrorAs(t, err, &received)
		var rejected *Error
		require.ErrorAs(t, err, &rejected)
		require.Equal(t, ErrCodeRequestRejected, rejected.ErrorCode)
		require.Equal(t, 1, dials)
	case <-ctx.Done():
		t.Fatal(context.Cause(ctx))
	}
}
