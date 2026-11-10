package http3_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go/http3"
	"github.com/quic-go/qpack"
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

func TestRequestBodyFirstReadUsesValidatedWireFields(t *testing.T) {
	for _, config := range []*http3.QPACKConfig{nil, {DynamicTable: true}} {
		t.Run(fmt.Sprint(config != nil), func(t *testing.T) {
			var calls int
			p := newQPACKStartupPair(t, config, nil, &http3.WireConfig{RequestBodyBufferSize: 16, RequestBodyFirstReadSizePolicy: func(info http3.RequestBodyReadInfo) int {
				calls++
				require.Equal(t, 16, info.BufferSize)
				fields := map[string]string{}
				for _, f := range info.HeaderFields {
					fields[f.Name] = f.Value
				}
				require.Equal(t, "POST", fields[":method"])
				require.Equal(t, "20", fields["content-length"])
				require.Equal(t, "gzip", fields["accept-encoding"])
				require.NotEmpty(t, fields["user-agent"])
				require.NotContains(t, fields, "header-order:")
				info.HeaderFields[0].Value = "mutated copy"
				return 5
			}})
			p.readControl(t)
			req, err := http.NewRequestWithContext(p.ctx, "POST", "https://localhost/upload", strings.NewReader("abcdefghijklmnopqrst"))
			require.NoError(t, err)
			req.Header["Content-Length"] = []string{"999"}
			req.Header["Header-Order:"] = []string{"content-length"}
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
			kind, block := readWireFrame(t, remote)
			require.EqualValues(t, 1, kind)
			decoder := qpack.NewDecoder().Decode(block)
			for {
				field, err := decoder()
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
				require.NotEqual(t, "mutated copy", field.Value)
			}
			var lengths []int
			var body bytes.Buffer
			for body.Len() < 20 {
				kind, data := readWireFrame(t, remote)
				require.Zero(t, kind)
				lengths = append(lengths, len(data))
				body.Write(data)
			}
			require.Equal(t, []int{5, 15}, lengths)
			require.Equal(t, "abcdefghijklmnopqrst", body.String())
			require.NoError(t, writeFrameQPACK(remote, 1, []byte{0, 0, 0xd9}))
			require.NoError(t, remote.Close())
			require.NoError(t, <-done)
			require.Equal(t, 1, calls)
		})
	}
}

func TestRequestBodyFirstReadInvalidPolicy(t *testing.T) {
	for _, size := range []int{-1, 17} {
		p := newQPACKStartupPair(t, &http3.QPACKConfig{DynamicTable: true}, nil, &http3.WireConfig{RequestBodyBufferSize: 16, RequestBodyFirstReadSizePolicy: func(http3.RequestBodyReadInfo) int { return size }})
		p.readControl(t)
		req, err := http.NewRequestWithContext(p.ctx, "POST", "https://localhost", strings.NewReader("payload"))
		require.NoError(t, err)
		_, err = p.h3.RoundTrip(req)
		var preparation *http3.RequestPreparationError
		require.ErrorAs(t, err, &preparation)
	}
}

// The first empty read must retain the cap. A subsequent short read consumes
// it without waiting for more producer data or limiting later reads.
type shortFirstUpload struct {
	io.Reader
	reads   int
	buffers []int
}

func (r *shortFirstUpload) Read(b []byte) (int, error) {
	r.reads++
	r.buffers = append(r.buffers, len(b))
	if r.reads == 1 {
		return 0, nil
	}
	if r.reads == 2 {
		b = b[:min(len(b), 2)]
	}
	return r.Reader.Read(b)
}

func TestRequestBodyFirstReadKeepsShortReads(t *testing.T) {
	for _, firstSize := range []int{0, 5, 16} {
		t.Run(fmt.Sprint(firstSize), func(t *testing.T) {
			p := newQPACKStartupPair(t, nil, nil, &http3.WireConfig{
				RequestBodyBufferSize:          16,
				RequestBodyFirstReadSizePolicy: func(http3.RequestBodyReadInfo) int { return firstSize },
			})
			p.readControl(t)
			body := &shortFirstUpload{Reader: strings.NewReader("abcdefghijklmnopqrst")}
			req, err := http.NewRequestWithContext(p.ctx, "POST", "https://localhost", body)
			require.NoError(t, err)
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
			for _, length := range []int{2, 16, 2} {
				kind, data := readWireFrame(t, remote)
				require.Zero(t, kind)
				require.Len(t, data, length)
			}
			_, err = remote.Read(make([]byte, 1))
			require.ErrorIs(t, err, io.EOF)
			require.NoError(t, writeFrameQPACK(remote, 1, []byte{0, 0, 0xd9}))
			require.NoError(t, remote.Close())
			require.NoError(t, <-done)
			limit := firstSize
			if limit == 0 {
				limit = 16
			}
			require.Equal(t, []int{limit, limit, 16}, body.buffers[:3])
		})
	}
}

type blockedUploadBody struct {
	started, closed chan struct{}
	once            sync.Once
}

func (b *blockedUploadBody) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.closed
	return 0, io.ErrClosedPipe
}
func (b *blockedUploadBody) Close() error {
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return nil
}

func TestRequestBodyCancellationAfterResponseHeaders(t *testing.T) {
	p := newQPACKStartupPair(t, nil, nil)
	p.readControl(t)
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()
	body := &blockedUploadBody{started: make(chan struct{}), closed: make(chan struct{})}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://localhost", body)
	require.NoError(t, err)
	responses := make(chan *http.Response, 1)
	errs := make(chan error, 1)
	go func() {
		rsp, err := p.h3.RoundTrip(req)
		if err != nil {
			errs <- err
		} else {
			responses <- rsp
		}
	}()
	remote, err := p.server.AcceptStream(p.ctx)
	require.NoError(t, err)
	kind, _ := readWireFrame(t, remote)
	require.EqualValues(t, 1, kind)
	require.NoError(t, writeFrameQPACK(remote, 1, []byte{0, 0, 0xd9}))
	var rsp *http.Response
	select {
	case rsp = <-responses:
	case err := <-errs:
		t.Fatal(err)
	case <-p.ctx.Done():
		t.Fatal(context.Cause(p.ctx))
	}
	defer rsp.Body.Close()
	select {
	case <-body.started:
	case <-p.ctx.Done():
		t.Fatal("upload read did not start")
	}
	cancel()
	select {
	case <-body.closed:
	case <-time.After(time.Second):
		t.Fatal("canceled upload reader was left blocked after response headers")
	}
}
