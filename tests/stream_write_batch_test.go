package quic_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/stretchr/testify/require"
)

type streamBatchTrace struct{ packets chan qlog.PacketSent }

func (r *streamBatchTrace) AddProducer() qlogwriter.Recorder { return r }
func (*streamBatchTrace) Close() error                       { return nil }
func (r *streamBatchTrace) RecordEvent(e qlogwriter.Event) {
	if p, ok := e.(qlog.PacketSent); ok && p.Header.PacketType == qlog.PacketType1RTT {
		p.Frames = append([]qlog.Frame(nil), p.Frames...)
		select {
		case r.packets <- p:
		default:
		}
	}
}

func streamBatchConnectionPair(t *testing.T, ctx context.Context, serverConfig, clientConfig *quic.Config) (*quic.Conn, *quic.Conn) {
	t.Helper()
	serverTLS := testdata.GetTLSConfig()
	serverTLS.NextProtos = []string{"stream-batch-test"}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, serverConfig)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	client, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{
		ServerName: "localhost", RootCAs: testdata.GetRootCA(), NextProtos: serverTLS.NextProtos,
	}, clientConfig)
	require.NoError(t, err)
	t.Cleanup(func() { client.CloseWithError(0, "") })
	server, err := listener.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { server.CloseWithError(0, "") })
	return client, server
}

func TestStreamWriteBatchOrderAndFIN(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	trace := &streamBatchTrace{packets: make(chan qlog.PacketSent, 64)}
	client, server := streamBatchConnectionPair(t, ctx, nil, &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }})
	control, err := client.OpenUniStream()
	require.NoError(t, err)
	request, err := client.OpenStream()
	require.NoError(t, err)
	n, err := client.TryWriteStreamBatch([]quic.StreamWrite{{StreamID: control.StreamID(), Data: []byte("priority")}, {StreamID: request.StreamID(), Data: []byte("headers"), Fin: true}})
	require.NoError(t, err)
	require.Equal(t, 2, n)
	incoming, err := server.AcceptStream(ctx)
	require.NoError(t, err)
	body, err := io.ReadAll(incoming)
	require.NoError(t, err)
	require.Equal(t, "headers", string(body))
	peerControl, err := server.AcceptUniStream(ctx)
	require.NoError(t, err)
	data := make([]byte, 8)
	_, err = io.ReadFull(peerControl, data)
	require.NoError(t, err)
	require.Equal(t, "priority", string(data))
	for {
		select {
		case packet := <-trace.packets:
			controlAt, requestAt := -1, -1
			for i, f := range packet.Frames {
				if sf, ok := f.Frame.(*qlog.StreamFrame); ok {
					if sf.StreamID == control.StreamID() {
						controlAt = i
					}
					if sf.StreamID == request.StreamID() {
						requestAt = i
						require.True(t, sf.Fin)
					}
				}
			}
			if requestAt >= 0 {
				require.GreaterOrEqual(t, controlAt, 0)
				require.Less(t, controlAt, requestAt)
				return
			}
		case <-ctx.Done():
			t.Fatal(context.Cause(ctx))
		}
	}
}

func TestStreamWriteBatchPartialAndValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, server := streamBatchConnectionPair(t, ctx, &quic.Config{InitialStreamReceiveWindow: 1024, MaxStreamReceiveWindow: 1024}, nil)
	control, err := client.OpenUniStream()
	require.NoError(t, err)
	request, err := client.OpenStream()
	require.NoError(t, err)
	for _, bad := range []quic.StreamID{-1, 1, 1 << 62, 4000} {
		n, err := client.TryWriteStreamBatch([]quic.StreamWrite{{StreamID: request.StreamID(), Data: []byte("must not be written")}, {StreamID: bad}})
		require.Error(t, err)
		require.Zero(t, n)
	}
	n, err := client.TryWriteStreamBatch([]quic.StreamWrite{{StreamID: control.StreamID(), Data: make([]byte, 1024)}})
	require.NoError(t, err)
	require.Equal(t, 1, n)
	n, err = client.TryWriteStreamBatch([]quic.StreamWrite{{StreamID: request.StreamID(), Data: []byte("only once"), Fin: true}, {StreamID: control.StreamID(), Data: []byte("blocked")}})
	require.ErrorIs(t, err, quic.ErrWouldBlock)
	require.Equal(t, 1, n)
	peer, err := server.AcceptStream(ctx)
	require.NoError(t, err)
	body, err := io.ReadAll(peer)
	require.NoError(t, err)
	require.Equal(t, "only once", string(body))
	n, err = client.TryWriteStreamBatch([]quic.StreamWrite{{StreamID: request.StreamID(), Data: []byte("closed")}})
	require.Error(t, err)
	require.Zero(t, n)
	n, err = client.TryWriteStreamBatch(make([]quic.StreamWrite, 65))
	require.ErrorIs(t, err, quic.ErrWouldBlock)
	require.Zero(t, n)
	n, err = client.TryWriteStreamBatch([]quic.StreamWrite{{StreamID: control.StreamID(), Data: make([]byte, (1<<20)+1)}})
	require.ErrorIs(t, err, quic.ErrWouldBlock)
	require.Zero(t, n)
	require.NoError(t, client.CloseWithError(0, "done"))
	<-client.Context().Done()
	_, err = client.TryWriteStreamBatch([]quic.StreamWrite{{StreamID: control.StreamID(), Data: []byte("closed connection")}})
	require.Error(t, err)
	require.False(t, errors.Is(err, quic.ErrWouldBlock))
}
