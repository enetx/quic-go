package http3_test

import (
	"testing"

	"github.com/enetx/http"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestHTTP3PriorityUpdateCanonicalAndSortedHeaders(t *testing.T) {
	p := newQPACKStartupPair(t, nil, nil, &http3.WireConfig{SendPriorityUpdates: true})
	control := wireControl(t, p)
	for _, tc := range []struct {
		headers http.Header
		want    string
	}{
		{http.Header{"Priority": []string{"u=3, i"}}, "i"},
		{http.Header{"Priority": []string{"i, u=2"}}, "u=2, i"},
		{http.Header{"Priority": []string{"u=0"}, "priority": []string{"u=5"}, "Header-Order:": []string{"priority"}}, "u=5"},
	} {
		stream, err := p.h3.OpenRequestStream(p.ctx)
		require.NoError(t, err)
		req, _ := http.NewRequestWithContext(p.ctx, "GET", "https://localhost/", nil)
		req.Header = tc.headers
		require.NoError(t, stream.SendRequestHeader(req))
		require.NoError(t, stream.Close())
		kind, payload := readWireFrame(t, control)
		require.EqualValues(t, 0xf0700, kind)
		_, n, err := quicvarint.Parse(payload)
		require.NoError(t, err)
		require.Equal(t, tc.want, string(payload[n:]))
	}
}

func TestHTTP3LivePriorityLowLevel(t *testing.T) {
	p := newQPACKStartupPair(t, nil, nil)
	control := wireControl(t, p)
	stream, err := p.h3.OpenRequestStream(p.ctx)
	require.NoError(t, err)
	require.Error(t, stream.UpdatePriority(1, false))
	request, _ := http.NewRequestWithContext(p.ctx, "GET", "https://localhost/", nil)
	require.NoError(t, stream.SendRequestHeader(request))
	require.NoError(t, stream.UpdatePriority(3, false))
	require.NoError(t, stream.UpdatePriority(1, true))
	require.NoError(t, stream.UpdatePriority(1, true))
	require.NoError(t, stream.UpdatePriority(3, false))
	for _, want := range []string{"u=1, i", ""} {
		kind, payload := readWireFrame(t, control)
		require.EqualValues(t, 0xf0700, kind)
		id, n, err := quicvarint.Parse(payload)
		require.NoError(t, err)
		require.EqualValues(t, stream.StreamID(), id)
		require.Equal(t, want, string(payload[n:]))
	}
	stream.CancelRead(0x10c)
	require.ErrorIs(t, stream.UpdatePriority(0, true), http3.ErrRequestCompleted)
}
