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
