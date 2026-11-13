package http3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	transportlog "github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/testutils/events"
	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

// Real QUIC streams with a deliberately held QPACK worker make partial batch
// acceptance deterministic, independent of goroutine scheduling and sleeps.
func newQPACKBatchClient(t *testing.T, options ...connPairOpt) (*ClientConn, *quic.Conn) {
	t.Helper()
	conn, peer := newConnPair(t, options...)
	stream, err := conn.OpenUniStream()
	require.NoError(t, err)
	ready := make(chan struct{})
	close(ready)
	owner := &rawConn{conn: conn}
	owner.clientQPACK = &clientQPACK{encoder: &clientQPACKStream{
		owner: owner, typ: QPACKEncoderStream, stream: stream, ready: ready,
		queue: make(chan []byte, 64), wake: make(chan struct{}, 1),
	}}
	c := &ClientConn{conn: conn, rawConn: owner, requestWriter: newRequestWriter()}
	c.configureWire(&WireConfig{CoalesceRequestHeaders: true})
	return c, peer
}

func qpackBatchRead(t *testing.T, stream io.Reader, length int) []byte {
	t.Helper()
	data := make([]byte, length)
	_, err := io.ReadFull(stream, data)
	require.NoError(t, err)
	return data
}

func qpackBatchRemoteEncoder(t *testing.T, peer *quic.Conn) *quic.ReceiveStream {
	t.Helper()
	stream, err := peer.AcceptUniStream(t.Context())
	require.NoError(t, err)
	require.NoError(t, stream.SetReadDeadline(time.Now().Add(5*time.Second)))
	return stream
}

func TestQPACKRequestBatchQueuesInstructionsHeadersAndFIN(t *testing.T) {
	var recorder events.Recorder
	c, peer := newQPACKBatchClient(t, withClientRecorder(&recorder))
	encoder := c.rawConn.clientQPACK.encoder
	require.NoError(t, encoder.enqueue([]byte{0x20}))
	require.NoError(t, encoder.enqueue([]byte{0x21}))
	c.requestWriter.encodeQPACK = func(quic.StreamID, []base.HeaderField) ([]byte, error) {
		require.NoError(t, encoder.enqueue([]byte{0x22}))
		return []byte{0, 0, 0xd1}, nil
	}
	stream, err := c.conn.OpenStream()
	require.NoError(t, err)
	req, err := http.NewRequest("GET", "https://localhost/", nil)
	require.NoError(t, err)
	require.NoError(t, c.requestWriter.WriteRequestHeader(&requestHeaderWriter{Writer: stream, fin: true}, req, false, stream.StreamID(), nil))

	request, err := peer.AcceptStream(t.Context())
	require.NoError(t, err)
	data, err := io.ReadAll(request)
	require.NoError(t, err)
	require.Equal(t, []byte{1, 3, 0, 0, 0xd1}, data)
	remoteEncoder := qpackBatchRemoteEncoder(t, peer)
	require.Equal(t, []byte{2, 0x20, 0x21, 0x22}, qpackBatchRead(t, remoteEncoder, 4))

	// Subsequent asynchronous output must not replay any accepted bytes or
	// append a second stream type, even though the worker starts after release.
	go encoder.run()
	require.NoError(t, encoder.enqueue([]byte{0x23}))
	require.Equal(t, []byte{0x23}, qpackBatchRead(t, remoteEncoder, 1))

	found := false
	for _, event := range recorder.Events(transportlog.PacketSent{}) {
		p := event.(transportlog.PacketSent)
		requestInPacket, encoderInPacket := false, false
		for _, f := range p.Frames {
			if sf, ok := f.Frame.(*transportlog.StreamFrame); ok {
				requestInPacket = requestInPacket || sf.StreamID == stream.StreamID() && sf.Length > 0 && sf.Fin
				encoderInPacket = encoderInPacket || sf.StreamID == encoder.stream.StreamID() && sf.Length >= 4
			}
		}
		found = found || requestInPacket && encoderInPacket
	}
	require.True(t, found, "ready encoder instructions and HEADERS used separate packets")
}

func TestQPACKRequestBatchPartialAcceptanceRetainsOnlyUnwrittenBytes(t *testing.T) {
	for _, blocked := range []string{"encoder", "request", "batch-size"} {
		t.Run(blocked, func(t *testing.T) {
			c, peer := newQPACKBatchClient(t, withServerStreamWindow(32))
			encoder := c.rawConn.clientQPACK.encoder
			request, err := c.conn.OpenStream()
			require.NoError(t, err)
			wr, finish := c.prepareQPACKRequestHeaders(&requestHeaderWriter{Writer: request, fin: true})
			defer finish()
			batch := wr.(*requestHeaderWriter).qpack
			require.NotNil(t, batch)
			instructions := bytes.Repeat([]byte{0x20}, 4)
			header := bytes.Repeat([]byte{0xd1}, 4)
			switch blocked {
			case "encoder":
				instructions = bytes.Repeat([]byte{0x20}, 64)
			case "request":
				header = bytes.Repeat([]byte{0xd1}, 64)
			case "batch-size":
				header = bytes.Repeat([]byte{0xd1}, 1<<20)
			}
			require.NoError(t, encoder.enqueue(instructions))
			done, err := c.tryQPACKRequestBatch(batch, nil, quic.StreamWrite{StreamID: request.StreamID(), Data: header, Fin: true})
			require.False(t, done)
			require.ErrorIs(t, err, quic.ErrWouldBlock)
			if blocked == "request" {
				require.Nil(t, encoder.pending, "the encoder write was already accepted")
			} else {
				require.Equal(t, instructions, encoder.pending)
			}
			batch.release()
			go encoder.run()

			// A remaining suffix is drained once by the original encoder stream.
			remote := qpackBatchRemoteEncoder(t, peer)
			want := append([]byte{2}, instructions...)
			require.Equal(t, want, qpackBatchRead(t, remote, len(want)))
			require.NoError(t, encoder.enqueue([]byte{0x21}))
			require.Equal(t, []byte{0x21}, qpackBatchRead(t, remote, 1))
		})
	}
}

func TestQPACKRequestBatchBlockedEncoderDoesNotHoldRequest(t *testing.T) {
	c, peer := newQPACKBatchClient(t, withServerStreamWindow(32))
	encoder := c.rawConn.clientQPACK.encoder
	request, err := c.conn.OpenStream()
	require.NoError(t, err)
	wr, finish := c.prepareQPACKRequestHeaders(&requestHeaderWriter{Writer: request})
	defer finish()
	instructions := bytes.Repeat([]byte{0x20}, 64)
	require.NoError(t, encoder.enqueue(instructions))
	req, err := http.NewRequest("GET", "https://localhost/", nil)
	require.NoError(t, err)
	require.NoError(t, c.writeRequestHeaders(wr, req, request.StreamID(), []byte{1, 0}))
	require.NoError(t, request.Close())
	go encoder.run()

	remote, err := peer.AcceptStream(t.Context())
	require.NoError(t, err)
	require.NoError(t, remote.SetReadDeadline(time.Now().Add(5*time.Second)))
	data, err := io.ReadAll(remote)
	require.NoError(t, err)
	require.Equal(t, []byte{1, 0}, data, "HEADERS waited for QPACK stream credit")
	remoteEncoder := qpackBatchRemoteEncoder(t, peer)
	require.Equal(t, append([]byte{2}, instructions...), qpackBatchRead(t, remoteEncoder, len(instructions)+1))
}

func TestQPACKRequestBatchPriorityPartialAcceptance(t *testing.T) {
	for _, blockedControl := range []bool{false, true} {
		name := "encoder-blocked"
		if blockedControl {
			name = "control-blocked"
		}
		t.Run(name, func(t *testing.T) {
			c, peer := newQPACKBatchClient(t, withServerStreamWindow(32))
			encoder := c.rawConn.clientQPACK.encoder
			control, err := c.conn.OpenUniStream()
			require.NoError(t, err)
			c.controlWriter.attachStream(control)
			c.wireConfig.SendPriorityUpdates = true
			var initial []byte
			instructions := bytes.Repeat([]byte{0x20}, 64)
			if blockedControl {
				initial = bytes.Repeat([]byte{0}, 32)
				require.NoError(t, control.TryWriteAll(initial))
				instructions = []byte{0x20}
			}
			request, err := c.conn.OpenStream()
			require.NoError(t, err)
			wr, finish := c.prepareQPACKRequestHeaders(&requestHeaderWriter{Writer: request, fin: true})
			defer finish()
			require.NoError(t, encoder.enqueue(instructions))
			req, _ := http.NewRequest("GET", "https://localhost/", nil)
			req.Header.Set("Priority", "u=0, i")
			priority := c.priorityUpdateFrame(request.StreamID(), 0, true)
			require.NoError(t, c.writeRequestHeaders(wr, req, request.StreamID(), []byte{1, 0}))
			go encoder.run()
			go c.controlWriter.run(control)

			remote, err := peer.AcceptStream(t.Context())
			require.NoError(t, err)
			require.NoError(t, remote.SetReadDeadline(time.Now().Add(5*time.Second)))
			data, err := io.ReadAll(remote)
			require.NoError(t, err)
			require.Equal(t, []byte{1, 0}, data)
			remoteEncoder := qpackBatchRemoteEncoder(t, peer)
			require.Equal(t, append([]byte{2}, instructions...), qpackBatchRead(t, remoteEncoder, len(instructions)+1))
			remoteControl := qpackBatchRemoteEncoder(t, peer)
			want := append(initial, priority...)
			require.Equal(t, want, qpackBatchRead(t, remoteControl, len(want)))
			// Observe the next asynchronous frame to catch both replay of an
			// accepted priority and reordering of a deferred priority frame.
			require.NoError(t, c.controlWriter.enqueue([]byte{0x21, 0}))
			require.Equal(t, []byte{0x21, 0}, qpackBatchRead(t, remoteControl, 2))
		})
	}
}

func TestQPACKRequestBatchValidationAndBusyWriterRelease(t *testing.T) {
	c, peer := newQPACKBatchClient(t)
	encoder := c.rawConn.clientQPACK.encoder
	stream, err := c.conn.OpenStream()
	require.NoError(t, err)
	req, err := http.NewRequest("GET", "https://localhost/", nil)
	require.NoError(t, err)
	req.Header["bad\nname"] = []string{"value"}
	require.Error(t, c.requestWriter.WriteRequestHeader(stream, req, false, stream.StreamID(), nil))
	require.True(t, encoder.writeMutex.TryLock(), "validation leaked the borrowed writer")

	// A busy critical writer must not delay preparation or the request itself.
	delete(req.Header, "bad\nname")
	require.NoError(t, c.requestWriter.WriteRequestHeader(stream, req, false, stream.StreamID(), nil))
	encoder.writeMutex.Unlock()
	require.NoError(t, stream.Close())
	remote, err := peer.AcceptStream(t.Context())
	require.NoError(t, err)
	require.NoError(t, remote.SetReadDeadline(time.Now().Add(5*time.Second)))
	data, err := io.ReadAll(remote)
	require.NoError(t, err)
	require.NotEmpty(t, data)
}

func TestQPACKRequestBatchConcurrentWriters(t *testing.T) {
	// The public transport tests exercise actual dynamic decoding and feedback.
	// This loop isolates writer leasing under concurrent requests, with a fresh
	// encoder instruction for every section and no artificial scheduling delay.
	c, peer := newQPACKBatchClient(t)
	encoder := c.rawConn.clientQPACK.encoder
	go encoder.run()
	var instructions atomic.Int32
	c.requestWriter.encodeQPACK = func(quic.StreamID, []base.HeaderField) ([]byte, error) {
		instructions.Add(1)
		return []byte{0, 0, 0xd1}, encoder.enqueue([]byte{0x20})
	}
	const requests = 24
	errorsOut := make(chan error, requests)
	for range requests {
		go func() {
			stream, err := c.conn.OpenStreamSync(t.Context())
			if err == nil {
				req, _ := http.NewRequest("GET", "https://localhost/", nil)
				err = c.requestWriter.WriteRequestHeader(stream, req, false, stream.StreamID(), nil)
				if closeErr := stream.Close(); err == nil {
					err = closeErr
				}
			}
			errorsOut <- err
		}()
	}
	for range requests {
		stream, err := peer.AcceptStream(t.Context())
		require.NoError(t, err)
		require.NoError(t, stream.SetReadDeadline(time.Now().Add(5*time.Second)))
		data, err := io.ReadAll(stream)
		require.NoError(t, err)
		require.Equal(t, []byte{1, 3, 0, 0, 0xd1}, data)
	}
	for range requests {
		require.NoError(t, <-errorsOut)
	}
	require.EqualValues(t, requests, instructions.Load())
	remote := qpackBatchRemoteEncoder(t, peer)
	require.Equal(t, append([]byte{2}, bytes.Repeat([]byte{0x20}, requests)...), qpackBatchRead(t, remote, requests+1))
}

func TestQPACKRequestBatchConnectionCancellation(t *testing.T) {
	c, _ := newQPACKBatchClient(t)
	stream, err := c.conn.OpenStream()
	require.NoError(t, err)
	wr, finish := c.prepareQPACKRequestHeaders(stream)
	defer finish()
	require.NoError(t, c.rawConn.clientQPACK.encoder.enqueue([]byte{0x20}))
	require.NoError(t, c.conn.CloseWithError(0, "closed before batch"))
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "https://localhost/", nil)
	err = c.writeRequestHeaders(wr, req, stream.StreamID(), []byte{1, 0})
	require.Error(t, err)
	require.False(t, errors.Is(err, quic.ErrWouldBlock))
	require.True(t, c.rawConn.clientQPACK.encoder.writeMutex.TryLock())
	c.rawConn.clientQPACK.encoder.writeMutex.Unlock()
}
