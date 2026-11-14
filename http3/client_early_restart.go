package http3

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
)

// earlyRestartClient owns successive HTTP/3 generations of one QUIC connection.
// Rejection retires the old workers before QUIC invalidates their streams. The
// verified application-ready hook creates the replacement exactly once.
type earlyRestartClient struct {
	conn     *quic.Conn
	current  atomic.Pointer[ClientConn]
	factory  func() *ClientConn
	rejected atomic.Bool
	staged   atomic.Bool
	ready    chan struct{}
	mu       sync.Mutex // serializes pool retirement with generation replacement
	retired  bool
}

func newEarlyRestartClient(client *ClientConn, factory func() *ClientConn) *earlyRestartClient {
	c := &earlyRestartClient{conn: client.conn, factory: factory, ready: make(chan struct{})}
	c.current.Store(client)
	return c
}

func (c *earlyRestartClient) reject() {
	// This hook is called synchronously before ResetFor0RTT. Canceling the
	// generation first prevents late workers from opening streams in new maps.
	c.rejected.Store(true)
	c.current.Load().rawConn.retireEarlyData()
}

func (c *earlyRestartClient) applicationReady() {
	if c.rejected.Load() && c.staged.CompareAndSwap(false, true) {
		c.mu.Lock()
		client := c.factory()
		if c.retired {
			client.retire()
		}
		c.current.Store(client)
		close(c.ready)
		c.mu.Unlock()
	}
}

func (c *earlyRestartClient) retire() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.retired = true
	c.current.Load().retire()
}

func (c *earlyRestartClient) active(ctx context.Context) (*ClientConn, error) {
	if !c.rejected.Load() {
		return c.current.Load(), nil
	}
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-c.conn.Context().Done():
		return nil, context.Cause(c.conn.Context())
	case <-c.ready:
		return c.current.Load(), nil
	}
}

func (c *earlyRestartClient) RoundTrip(req *http.Request) (*http.Response, error) {
	client, err := c.active(req.Context())
	if err != nil {
		return nil, err
	}
	response, err := client.RoundTrip(req)
	if !errors.Is(err, quic.Err0RTTRejected) || req.Context().Err() != nil {
		return response, err
	}
	client, waitErr := c.active(req.Context())
	if waitErr != nil {
		return nil, waitErr
	}
	// A successful handshake must never replay requests on the retired HTTP/3
	// generation. Rejection is one-shot for this QUIC connection.
	if !c.rejected.Load() {
		return nil, err
	}
	retry := *req
	reopened := false
	switch retry.Method {
	case MethodGet0RTT:
		retry.Method = http.MethodGet
	case MethodHead0RTT:
		retry.Method = http.MethodHead
	}
	if retry.Body != nil && retry.Body != http.NoBody {
		if _, unopened := errors.AsType[*errConnUnusable](err); !unopened {
			if retry.GetBody == nil {
				return nil, err
			}
			retry.Body, waitErr = retry.GetBody()
			if waitErr != nil {
				return nil, waitErr
			}
			retry.Body = &requestBodyCloser{ReadCloser: retry.Body}
			reopened = true
		}
	}
	response, err = client.RoundTrip(&retry)
	if err != nil && reopened {
		retry.Body.Close()
	}
	return response, err
}

func (c *earlyRestartClient) OpenRequestStream(ctx context.Context) (*RequestStream, error) {
	client, err := c.active(ctx)
	if err != nil {
		return nil, err
	}
	return client.OpenRequestStream(ctx)
}

func (c *earlyRestartClient) handleUnidirectionalStream(stream *quic.ReceiveStream) {
	client, err := c.active(c.conn.Context())
	if err == nil {
		client.handleUnidirectionalStream(stream)
	}
}
