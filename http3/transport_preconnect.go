package http3

import (
	"context"
	"net"
)

// Preconnect prepares a pooled HTTP/3 connection to address (host:port),
// waiting for the verified TLS handshake without sending an HTTP request.
// Connection SETTINGS and stream setup retain the transport's normal behavior.
// Cancellation releases this caller; a shared connection used by another caller
// is retained. Otherwise a failed or abandoned attempt is removed and closed.
func (t *Transport) Preconnect(ctx context.Context, address string) error {
	if _, _, err := net.SplitHostPort(address); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	t.initOnce.Do(func() { t.initErr = t.init() })
	if t.initErr != nil {
		return t.initErr
	}
	client, _, err := t.getClient(ctx, address, false)
	if err != nil {
		return err
	}
	var failed bool
	defer func() {
		t.mutex.Lock()
		closeAttempt := client.useCount.Add(-1) == 0 && failed && t.clients[address] == client
		if closeAttempt {
			delete(t.clients, address)
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
		return err
	}
	if client.dialErr != nil {
		failed = true
		return client.dialErr
	}
	select {
	case <-client.conn.HandshakeComplete():
	case <-client.conn.Context().Done():
		failed = true
		return context.Cause(client.conn.Context())
	case <-ctx.Done():
		failed = true
		return context.Cause(ctx)
	}
	if client.conn.Context().Err() != nil {
		failed = true
		return context.Cause(client.conn.Context())
	}
	if ctx.Err() != nil {
		failed = true
		return context.Cause(ctx)
	}
	return nil
}
