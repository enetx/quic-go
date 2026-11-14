package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/stretchr/testify/require"
)

type cacheMissBody struct{ reads, closes int }

func (b *cacheMissBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *cacheMissBody) Close() error             { b.closes++; return nil }

func TestReadyCacheProbeDoesNotJoinPendingDialOrTakeBody(t *testing.T) {
	started := make(chan struct{})
	transport := &Transport{Dial: func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, context.Cause(ctx)
	}}
	defer transport.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	prepared := make(chan error, 1)
	go func() { prepared <- transport.Preconnect(ctx, "localhost:443") }()
	<-started
	body := new(cacheMissBody)
	request, err := http.NewRequestWithContext(t.Context(), "POST", "https://localhost/", body)
	require.NoError(t, err)
	response, err := transport.RoundTripCachedReady(request)
	require.Nil(t, response)
	require.ErrorIs(t, err, ErrNoCachedConn)
	require.Zero(t, body.reads)
	require.Zero(t, body.closes)

	// The existing API retains its ability to join a pending pooled dial.
	legacyContext, cancelLegacy := context.WithCancel(t.Context())
	legacyDone := make(chan error, 1)
	go func() {
		_, err := transport.RoundTripCached(request.WithContext(legacyContext))
		legacyDone <- err
	}()
	require.Eventually(t, func() bool {
		transport.mutex.Lock()
		defer transport.mutex.Unlock()
		return transport.clients["localhost:443"].useCount.Load() == 2
	}, time.Second, time.Millisecond)
	cancelLegacy()
	require.ErrorIs(t, <-legacyDone, context.Canceled)
	require.Zero(t, body.reads)
	require.Equal(t, 1, body.closes)
	cancel()
	require.ErrorIs(t, <-prepared, context.Canceled)
}

func TestDrainingPoolOwnerKeepsActiveBodyAndClosesWithTransport(t *testing.T) {
	for _, closeAll := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle cleanup", true: "full close"}[closeAll], func(t *testing.T) {
			transport, port, dials := reuseTestTransport(t)
			address := "localhost:" + port
			response := reuseRequest(t, transport, address, false)
			defer response.Body.Close()
			old := transport.clients[address]
			nativeClient(old.clientConn).goAwayCancel()
			require.NoError(t, transport.Preconnect(t.Context(), address))
			require.EqualValues(t, 2, dials.Load())
			require.Contains(t, transport.retired, old)
			require.NotSame(t, old, transport.clients[address])
			if closeAll {
				require.NoError(t, transport.Close())
				require.Error(t, old.conn.Context().Err(), "full close must retain ownership of drained sessions")
				return
			}
			transport.CloseIdleConnections()
			require.NoError(t, old.conn.Context().Err(), "a draining session's active response still owns its connection")
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			require.Equal(t, address, string(body))
			require.NoError(t, response.Body.Close())
			transport.CloseIdleConnections()
			require.Error(t, old.conn.Context().Err())
		})
	}
}

func TestHasCachedConnectionUsesExactConfirmedPoolPartition(t *testing.T) {
	tr, port, dials := reuseTestTransport(t)
	type partitionKey struct{}
	tr.ConnectionPoolPartition = func(ctx context.Context, _ string) string {
		value, _ := ctx.Value(partitionKey{}).(string)
		return value
	}
	first := context.WithValue(t.Context(), partitionKey{}, "first")
	other := context.WithValue(t.Context(), partitionKey{}, "other")
	address := "localhost:" + port
	require.False(t, tr.HasCachedConnection(first, address))
	require.Zero(t, dials.Load())
	require.NoError(t, tr.Preconnect(first, address))
	require.True(t, tr.HasCachedConnection(first, address))
	require.False(t, tr.HasCachedConnection(other, address))
	require.False(t, tr.HasCachedConnection(first, "invalid-address"))
	require.EqualValues(t, 1, dials.Load())

	canceled, cancel := context.WithCancel(first)
	cancel()
	require.False(t, tr.HasCachedConnection(canceled, address))
	key, _ := tr.clientPoolKey(first, address)
	nativeClient(tr.clients[key].clientConn).goAwayCancel()
	require.False(t, tr.HasCachedConnection(first, address), "GOAWAY retires the exact session")
	require.NoError(t, tr.Close())
	require.False(t, tr.HasCachedConnection(first, address))
}

func TestRoundTripCachedMissPreservesRequestBodyOwnership(t *testing.T) {
	tr := &Transport{Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
		t.Error("cache probe dialed")
		return nil, errors.New("unexpected dial")
	}}
	defer tr.Close()
	body := new(cacheMissBody)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://localhost:443/", body)
	require.NoError(t, err)
	_, err = tr.RoundTripCached(req)
	require.ErrorIs(t, err, ErrNoCachedConn)
	require.Zero(t, body.reads)
	require.Zero(t, body.closes)
	_, err = tr.RoundTripOpt(req, RoundTripOpt{OnlyCachedConn: true})
	require.ErrorIs(t, err, ErrNoCachedConn)
	require.Equal(t, 1, body.closes, "the existing API keeps its normal ownership contract")
}

func reuseTestTransport(t *testing.T) (*Transport, string, *atomic.Int32) {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { udp.Close() })
	server := &Server{TLSConfig: testdata.GetTLSConfig(), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.Host))
	})}
	t.Cleanup(func() { server.Close() })
	go server.Serve(udp)
	calls := new(atomic.Int32)
	tr := &Transport{TLSClientConfig: &tls.Config{RootCAs: testdata.GetRootCA(), ServerName: "localhost"}}
	tr.Dial = func(ctx context.Context, _ string, cfg *tls.Config, q *quic.Config) (*quic.Conn, error) {
		calls.Add(1)
		return quic.DialAddr(ctx, udp.LocalAddr().String(), cfg, q)
	}
	t.Cleanup(func() { tr.Close() })
	_, port, err := net.SplitHostPort(udp.LocalAddr().String())
	require.NoError(t, err)
	return tr, port, calls
}

func reuseRequest(t *testing.T, tr *Transport, authority string, consume bool) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+authority, nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	if consume {
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)
		resp.Body.Close()
	}
	return resp
}

func TestCoalescingUsesSingleOwnerAndPreservesActiveBodies(t *testing.T) {
	tr, port, calls := reuseTestTransport(t)
	a, b := "localhost:"+port, "127.0.0.1:"+port
	first := reuseRequest(t, tr, a, false)
	defer first.Body.Close()
	tr.ConnectionReusePolicy = func(_ context.Context, info ConnectionReuseInfo) bool {
		require.Equal(t, a, info.OriginalAuthority)
		require.Equal(t, b, info.Authority)
		tr.CloseIdleConnections() // Callback is outside locks; its candidate is pinned.
		return true
	}
	reuseRequest(t, tr, b, true)
	require.EqualValues(t, 1, calls.Load())
	require.Len(t, tr.clients, 1, "coalescing must not duplicate connection ownership")
	tr.CloseIdleConnections()
	data, err := io.ReadAll(first.Body)
	require.NoError(t, err)
	require.Equal(t, a, string(data), "an unrelated idle close must not interrupt an active body")
}

func TestCoalescingRechecksCancellationClosureAndGoAway(t *testing.T) {
	for _, scenario := range []string{"cancel", "close", "goaway", "deny"} {
		t.Run(scenario, func(t *testing.T) {
			tr, port, calls := reuseTestTransport(t)
			a := "localhost:" + port
			reuseRequest(t, tr, a, true)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			tr.ConnectionReusePolicy = func(context.Context, ConnectionReuseInfo) bool {
				switch scenario {
				case "cancel":
					cancel()
				case "close":
					require.NoError(t, tr.Close())
				case "deny":
					return false
				}
				return true
			}
			if scenario == "goaway" {
				nativeClient(tr.clients[a].clientConn).goAwayCancel()
			}
			req, err := http.NewRequestWithContext(ctx, "GET", "https://127.0.0.1:"+port, nil)
			require.NoError(t, err)
			resp, err := tr.RoundTrip(req)
			switch scenario {
			case "cancel":
				require.ErrorIs(t, err, context.Canceled)
				require.EqualValues(t, 1, calls.Load())
			case "close":
				require.ErrorIs(t, err, ErrTransportClosed)
				require.EqualValues(t, 1, calls.Load())
			default:
				require.NoError(t, err)
				_, err = io.Copy(io.Discard, resp.Body)
				require.NoError(t, err)
				resp.Body.Close()
				require.EqualValues(t, 2, calls.Load())
			}
		})
	}
}

func TestCoalescingRequiresMatchingRequestAuthority(t *testing.T) {
	tr, port, calls := reuseTestTransport(t)
	reuseRequest(t, tr, "localhost:"+port, true)
	tr.ConnectionReusePolicy = func(context.Context, ConnectionReuseInfo) bool {
		t.Error("explicitly different wire authority must not enter automatic coalescing")
		return true
	}
	req, err := http.NewRequestWithContext(t.Context(), "POST", "https://127.0.0.1:"+port, strings.NewReader("body"))
	require.NoError(t, err)
	req.Host = "custom.example"
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.EqualValues(t, 2, calls.Load())
}

func TestPoolPartitionAppliesToExactLookupCoalescingAndPreconnect(t *testing.T) {
	type partitionKey struct{}
	for _, coalesce := range []bool{false, true} {
		t.Run(map[bool]string{false: "dedicated", true: "coalesced"}[coalesce], func(t *testing.T) {
			tr, port, calls := reuseTestTransport(t)
			tr.ConnectionPoolPartition = func(ctx context.Context, _ string) string {
				value, _ := ctx.Value(partitionKey{}).(string)
				return value
			}
			if coalesce {
				tr.ConnectionReusePolicy = func(context.Context, ConnectionReuseInfo) bool { return true }
			}
			for _, attempt := range []struct{ authority, partition string }{
				{"localhost:" + port, "one"}, {"localhost:" + port, "two"},
				{"127.0.0.1:" + port, "one"},
			} {
				ctx := context.WithValue(t.Context(), partitionKey{}, attempt.partition)
				req, err := http.NewRequestWithContext(ctx, "GET", "https://"+attempt.authority, nil)
				require.NoError(t, err)
				resp, err := tr.RoundTrip(req)
				require.NoError(t, err)
				_, err = io.Copy(io.Discard, resp.Body)
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())
				require.NoError(t, tr.Preconnect(ctx, attempt.authority))
			}
			want := 3
			if coalesce {
				want = 2
			}
			require.EqualValues(t, want, calls.Load())
			require.Len(t, tr.clients, want, "preconnect must retain single ownership of a borrowed connection")
		})
	}
}

func TestCloseIdleConnectionsJoinsPendingDialAfterRequestCancellation(t *testing.T) {
	tr, port, _ := reuseTestTransport(t)
	dial := tr.Dial
	connected, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	tr.Dial = func(ctx context.Context, addr string, tlsConfig *tls.Config, q *quic.Config) (*quic.Conn, error) {
		conn, err := dial(ctx, addr, tlsConfig, q)
		close(connected)
		<-release
		return conn, err
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "GET", "https://localhost:"+port, nil)
	require.NoError(t, err)
	result := make(chan error, 1)
	go func() {
		_, err := tr.RoundTrip(request)
		result <- err
	}()
	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("dial did not establish a connection")
	}
	cancel()
	require.ErrorIs(t, <-result, context.Canceled)
	closed := make(chan struct{})
	go func() { tr.CloseIdleConnections(); close(closed) }()
	close(release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("idle closure did not join the abandoned dial")
	}
	require.Empty(t, tr.clients)
}
