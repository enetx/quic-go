package http3

import (
	"context"
	"net"

	"github.com/enetx/quic-go"
)

// Preconnect prepares a pooled HTTP/3 connection to address (host:port),
// waiting for the verified TLS handshake without sending an HTTP request.
// Connection SETTINGS and stream setup retain the transport's normal behavior.
// Cancellation releases this caller; a shared connection used by another caller
// is retained. Otherwise a failed or abandoned attempt is removed and closed.
func (t *Transport) Preconnect(ctx context.Context, address string) error {
	_, err := t.preconnect(ctx, address, false)
	return err
}

// PreconnectEarly prepares a pooled connection without sending an HTTP request.
// It returns when cached 0-RTT keys are available, or after the full handshake
// when early data is unavailable. The returned connection remains owned by the
// transport. Early readiness does not authenticate the current handshake.
// A custom Dial callback must itself support returning an early connection.
func (t *Transport) PreconnectEarly(ctx context.Context, address string) (*quic.Conn, error) {
	return t.preconnect(ctx, address, true)
}

func (t *Transport) preconnect(ctx context.Context, address string, early bool) (*quic.Conn, error) {
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	t.initOnce.Do(func() { t.initErr = t.init() })
	if t.initErr != nil {
		return nil, t.initErr
	}
	client, _, err := t.getClient(ctx, address, false)
	if err != nil {
		return nil, err
	}
	var failed bool
	defer func() {
		t.mutex.Lock()
		closeAttempt := client.useCount.Add(-1) == 0 && failed && client.authority == address && t.clients[client.poolKey] == client
		if closeAttempt {
			delete(t.clients, client.poolKey)
		}
		t.mutex.Unlock()
		if closeAttempt {
			client.Close()
		}
	}()
	wait := func(done <-chan struct{}) error {
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	if err := wait(client.dialing); err != nil {
		failed = true
		return nil, err
	}
	if client.dialErr != nil {
		failed = true
		return nil, client.dialErr
	}
	if !early {
		select {
		case <-client.conn.HandshakeComplete():
		case <-client.conn.Context().Done():
			failed = true
			return nil, context.Cause(client.conn.Context())
		case <-ctx.Done():
			failed = true
			return nil, context.Cause(ctx)
		}
	}
	if client.conn.Context().Err() != nil {
		failed = true
		return nil, context.Cause(client.conn.Context())
	}
	if ctx.Err() != nil {
		failed = true
		return nil, context.Cause(ctx)
	}
	return client.conn, nil
}
