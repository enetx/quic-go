package http3_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/enetx/http"
	"github.com/enetx/quic-go/http3"
	"github.com/stretchr/testify/require"
)

func TestRequestBodyFraming(t *testing.T) {
	for _, tc := range []struct {
		name          string
		buffer, frame int
		unknown       bool
		want          []int
	}{
		{"native", 0, 0, false, []int{8192, 8192, 616}},
		{"buffer", 5000, 0, false, []int{5000, 5000, 5000, 2000}},
		{"split", 5000, 2000, false, []int{2000, 2000, 1000, 2000, 2000, 1000, 2000, 2000, 1000, 2000}},
		{"unknown", 5000, 2000, true, []int{2000, 2000, 1000, 2000, 2000, 1000, 2000, 2000, 1000, 2000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newQPACKStartupPair(t, nil, nil, &http3.WireConfig{RequestBodyBufferSize: tc.buffer, MaxDataFrameSize: tc.frame})
			p.readControl(t)
			body := strings.Repeat("a", 17000)
			req, err := http.NewRequestWithContext(p.ctx, "POST", "https://localhost/upload", strings.NewReader(body))
			require.NoError(t, err)
			if tc.unknown {
				req.ContentLength = -1
			}
			done := make(chan error, 1)
			go func() {
				rsp, err := p.h3.RoundTrip(req)
				if err == nil {
					_, err = io.Copy(io.Discard, rsp.Body)
					rsp.Body.Close()
				}
				done <- err
			}()
			remote, err := p.server.AcceptStream(p.ctx)
			require.NoError(t, err)
			kind, _ := readWireFrame(t, remote)
			require.EqualValues(t, 1, kind)
			var lengths []int
			var received bytes.Buffer
			for received.Len() < len(body) {
				kind, data := readWireFrame(t, remote)
				require.Zero(t, kind)
				lengths = append(lengths, len(data))
				received.Write(data)
			}
			require.Equal(t, tc.want, lengths)
			require.Equal(t, body, received.String())
			_, err = remote.Read(make([]byte, 1))
			require.ErrorIs(t, err, io.EOF)
			require.NoError(t, writeFrameQPACK(remote, 1, []byte{0, 0, 0xd9}))
			require.NoError(t, remote.Close())
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-p.ctx.Done():
				t.Fatal(context.Cause(p.ctx))
			}
		})
	}
}

func TestRequestBodyPolicyValidation(t *testing.T) {
	for _, size := range []int{-1, 16<<20 + 1} {
		config := &http3.WireConfig{RequestBodyBufferSize: size}
		require.Error(t, config.Validate())
		config = &http3.WireConfig{MaxDataFrameSize: size}
		require.Error(t, config.Validate())
		p := newQPACKStartupPair(t, nil, nil, &http3.WireConfig{RequestBodyBufferSizePolicy: func(length int64) int { require.EqualValues(t, 3, length); return size }})
		p.readControl(t)
		req, err := http.NewRequestWithContext(p.ctx, "POST", "https://localhost", strings.NewReader("abc"))
		require.NoError(t, err)
		_, err = p.h3.RoundTrip(req)
		var preparation *http3.RequestPreparationError
		require.ErrorAs(t, err, &preparation)
	}
}
