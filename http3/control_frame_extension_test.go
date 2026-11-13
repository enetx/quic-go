package http3

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/enetx/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestControlExtensionReaderIsBoundedAndDrainsUnreadPayload(t *testing.T) {
	var raw []byte
	raw = quicvarint.Append(raw, 0xc)
	raw = quicvarint.Append(raw, 6)
	raw = append(raw, "origin"...)
	raw = append(raw, 0, 3, 'g', 'e', 't') // Next DATA frame must remain intact.
	r := bytes.NewReader(raw)
	calls := 0
	p := &frameParser{r: r, onUnknownFrame: func(frame ControlFrame) error {
		calls++
		require.EqualValues(t, 12, frame.Type)
		require.EqualValues(t, 6, frame.Length)
		b := make([]byte, 2)
		_, err := io.ReadFull(frame.Payload, b)
		require.Equal(t, "or", string(b))
		return err
	}}
	f, err := p.ParseNext(nil)
	require.NoError(t, err)
	require.EqualValues(t, 3, f.(*dataFrame).Length)
	require.Equal(t, 1, calls)
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, "get", string(b))
}

func TestControlExtensionCannotHideTruncationOrParserErrors(t *testing.T) {
	failure := errors.New("extension rejected")
	for _, callback := range []func(ControlFrame) error{
		func(ControlFrame) error { return nil },
		func(frame ControlFrame) error { _, err := io.Copy(io.Discard, frame.Payload); return err },
		func(ControlFrame) error { return failure },
	} {
		p := &frameParser{r: bytes.NewReader([]byte{12, 4, 'x'}), onUnknownFrame: callback}
		_, err := p.ParseNext(nil)
		require.Error(t, err)
	}
	// No callback retains native unknown-frame handling, including request streams.
	p := &frameParser{r: bytes.NewReader([]byte{12, 0, 0, 0})}
	f, err := p.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &dataFrame{}, f)
}
