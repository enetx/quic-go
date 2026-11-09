package http3_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/quicvarint"
	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func readWireFrame(t *testing.T, stream io.Reader) (uint64, []byte) {
	t.Helper()
	r := quicvarint.NewReader(stream)
	kind, err := quicvarint.Read(r)
	require.NoError(t, err)
	length, err := quicvarint.Read(r)
	require.NoError(t, err)
	require.Less(t, length, uint64(4<<20))
	data := make([]byte, length)
	_, err = io.ReadFull(stream, data)
	require.NoError(t, err)
	return kind, data
}

func wireControl(t *testing.T, p *qpackStartupPair) *quic.ReceiveStream {
	t.Helper()
	stream, err := p.server.AcceptUniStream(p.ctx)
	require.NoError(t, err)
	deadline, _ := p.ctx.Deadline()
	stream.SetReadDeadline(deadline)
	typ, err := quicvarint.Read(quicvarint.NewReader(stream))
	require.NoError(t, err)
	require.Zero(t, typ)
	kind, _ := readWireFrame(t, stream)
	require.EqualValues(t, 4, kind, "SETTINGS must be first")
	return stream
}

func TestHTTP3WireFramesAreIndependent(t *testing.T) {
	for _, grease := range []bool{false, true} {
		for _, updates := range []bool{false, true} {
			t.Run(fmt.Sprintf("grease=%v/updates=%v", grease, updates), func(t *testing.T) {
				config := &http3.WireConfig{SendPriorityUpdates: updates}
				var calls atomic.Int32
				if grease {
					config.ControlGreaseFrames = func() ([]http3.GreaseFrame, error) {
						calls.Add(1)
						return []http3.GreaseFrame{{Type: 33, Payload: []byte("control")}}, nil
					}
					config.RequestGreaseFrames = func(req *http.Request) ([]http3.GreaseFrame, error) {
						return []http3.GreaseFrame{{Type: 64, Payload: []byte(req.URL.Path)}}, nil
					}
				}
				p := newQPACKStartupPair(t, nil, nil, config)
				config.SendPriorityUpdates = !updates // connection already owns its snapshot
				control := wireControl(t, p)
				if grease {
					kind, data := readWireFrame(t, control)
					require.EqualValues(t, 33, kind)
					require.Equal(t, "control", string(data))
				}
				for i, priority := range []string{"u=0, i", "u=3", "u=5"} {
					stream, err := p.h3.OpenRequestStream(p.ctx)
					require.NoError(t, err)
					req, err := http.NewRequestWithContext(p.ctx, "GET", fmt.Sprintf("https://localhost/%d", i), nil)
					require.NoError(t, err)
					req.Header["priority"] = []string{priority}
					require.NoError(t, stream.SendRequestHeader(req))
					require.NoError(t, stream.Close())
					remote, err := p.server.AcceptStream(p.ctx)
					require.NoError(t, err)
					if grease {
						kind, data := readWireFrame(t, remote)
						require.EqualValues(t, 64, kind)
						require.Equal(t, req.URL.Path, string(data))
					}
					kind, block := readWireFrame(t, remote)
					require.EqualValues(t, 1, kind)
					decode := base.NewDecoder().Decode(block)
					for {
						_, err = decode()
						if err == io.EOF {
							break
						}
						require.NoError(t, err)
					}
					if updates && i != 1 {
						kind, data := readWireFrame(t, control)
						require.EqualValues(t, 0xf0700, kind)
						id, n, err := quicvarint.Parse(data)
						require.NoError(t, err)
						require.EqualValues(t, remote.StreamID(), id)
						require.Equal(t, priority, string(data[n:]))
					}
				}
				control.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
				_, err := quicvarint.Read(quicvarint.NewReader(control))
				var timeout net.Error
				require.ErrorAs(t, err, &timeout)
				require.True(t, timeout.Timeout(), "unexpected extra control frame")
				if grease {
					require.EqualValues(t, 1, calls.Load())
				}
			})
		}
	}
}

func TestHTTP3ControlStreamStopClosesConnection(t *testing.T) {
	p := newQPACKStartupPair(t, nil, nil, &http3.WireConfig{SendPriorityUpdates: true})
	control := wireControl(t, p)
	control.CancelRead(42)
	select {
	case <-p.client.Context().Done():
	case <-p.ctx.Done():
		t.Fatal("closed control stream was ignored")
	}
}

func TestHTTP3BlockedControlStreamHasBoundedQueue(t *testing.T) {
	p := newQPACKStartupPair(t, nil, &quic.Config{InitialStreamReceiveWindow: 1024, MaxStreamReceiveWindow: 1024, MaxIncomingStreams: 100}, &http3.WireConfig{
		SendPriorityUpdates: true,
		ControlGreaseFrames: func() ([]http3.GreaseFrame, error) {
			return []http3.GreaseFrame{{Type: 33, Payload: bytes.Repeat([]byte{1}, 2<<20)}}, nil
		},
	})
	var queueErr error
	for range 70 {
		stream, err := p.h3.OpenRequestStream(p.ctx)
		require.NoError(t, err)
		req, _ := http.NewRequestWithContext(p.ctx, "GET", "https://localhost/", nil)
		req.Header.Set("Priority", "u=0")
		queueErr = stream.SendRequestHeader(req)
		stream.Close()
		if queueErr != nil {
			break
		}
	}
	require.ErrorContains(t, queueErr, "queue is full")
}

func TestHTTP3ControlFactoryFailure(t *testing.T) {
	for _, factory := range []func() ([]http3.GreaseFrame, error){
		func() ([]http3.GreaseFrame, error) { return nil, errors.New("factory failure") },
		func() ([]http3.GreaseFrame, error) { return []http3.GreaseFrame{{Type: 4}}, nil },
	} {
		p := newQPACKStartupPair(t, nil, nil, &http3.WireConfig{ControlGreaseFrames: factory})
		select {
		case <-p.client.Context().Done():
		case <-p.ctx.Done():
			t.Fatal("invalid factory was ignored")
		}
	}
}
