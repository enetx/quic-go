package qpack_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"sync"
	"testing"

	dynamic "github.com/enetx/quic-go/internal/qpack"
	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
func process(t *testing.T, d *dynamic.Decoder, b []byte) {
	t.Helper()
	require.ErrorIs(t, d.ReadEncoder(bytes.NewReader(b)), io.EOF)
}
func pref(prefix byte, flags byte, v uint64) []byte {
	mask := uint64(1<<prefix) - 1
	if v < mask {
		return []byte{flags | byte(v)}
	}
	b := []byte{flags | byte(mask)}
	v -= mask
	for v >= 128 {
		b = append(b, byte(v&127)|128)
		v >>= 7
	}
	return append(b, byte(v))
}
func literal(name, value string) []byte {
	b := pref(5, 0x40, uint64(len(name)))
	b = append(b, name...)
	b = append(b, pref(7, 0, uint64(len(value)))...)
	return append(b, value...)
}
func TestRFC9204AppendixB(t *testing.T) {
	var feedback []byte
	d := dynamic.NewDecoder(220, 1, func(b []byte) error { feedback = append(feedback, b...); return nil })
	fields, err := d.Decode(context.Background(), 0, unhex(t, "0000510b2f696e6465782e68746d6c"), 1024, nil)
	require.NoError(t, err)
	require.Equal(t, []base.HeaderField{{Name: ":path", Value: "/index.html"}}, fields)
	process(t, d, unhex(t, "3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468"))
	fields, err = d.Decode(context.Background(), 4, unhex(t, "03811011"), 1024, nil)
	require.NoError(t, err)
	require.Equal(t, []base.HeaderField{{Name: ":authority", Value: "www.example.com"}, {Name: ":path", Value: "/sample/path"}}, fields)
	require.Equal(t, []byte{1, 1, 0x84}, feedback)
	process(t, d, unhex(t, "4a637573746f6d2d6b65790c637573746f6d2d76616c7565"))
	process(t, d, []byte{2}) // duplicate absolute entry 0
	fields, err = d.Decode(context.Background(), 8, unhex(t, "050080c181"), 1024, nil)
	require.NoError(t, err)
	require.Equal(t, []base.HeaderField{{Name: ":authority", Value: "www.example.com"}, {Name: ":path", Value: "/"}, {Name: "custom-key", Value: "custom-value"}}, fields)
	process(t, d, unhex(t, "810d637573746f6d2d76616c756532")) // oldest entry evicted
	fields, err = d.Decode(context.Background(), 12, []byte{6, 0, 0x80}, 1024, nil)
	require.NoError(t, err)
	require.Equal(t, []base.HeaderField{{Name: "custom-key", Value: "custom-value2"}}, fields)
	_, err = d.Decode(context.Background(), 16, []byte{6, 0, 0x84}, 1024, nil)
	require.ErrorIs(t, err, dynamic.ErrDecompression)
}
func TestAllFieldRepresentations(t *testing.T) {
	d := dynamic.NewDecoder(128, 1, nil)
	process(t, d, append(pref(5, 0x20, 128), literal("x-name", "original")...))
	// RIC=1/Base=1: indexed relative, literal relative with N=1, static name,
	// literal name (Huffman), preserving the field section's order.
	block := []byte{2, 0, 0x80, 0x60, 3, 'n', 'e', 'w', 0x51, 1, '/'}
	name := hpack.AppendHuffmanString(nil, "abc")
	block = append(block, pref(3, 0x28, uint64(len(name)))...)
	block = append(block, name...)
	block = append(block, 1, 'v')
	fields, err := d.Decode(context.Background(), 0, block, 1024, nil)
	require.NoError(t, err)
	require.Equal(t, []base.HeaderField{{Name: "x-name", Value: "original"}, {Name: "x-name", Value: "new"}, {Name: ":path", Value: "/"}, {Name: "abc", Value: "v"}}, fields)
	// Base=0: indexed post-base and literal post-base name, including N=1.
	fields, err = d.Decode(context.Background(), 4, []byte{2, 0x80, 0x10, 0x08, 1, 'v'}, 1024, nil)
	require.NoError(t, err)
	require.Equal(t, []base.HeaderField{{Name: "x-name", Value: "original"}, {Name: "x-name", Value: "v"}}, fields)
}
func TestHuffmanInstructions(t *testing.T) {
	d := dynamic.NewDecoder(256, 1, nil)
	process(t, d, pref(5, 0x20, 256))
	name, value := hpack.AppendHuffmanString(nil, "custom-key"), hpack.AppendHuffmanString(nil, "custom-value")
	instruction := pref(5, 0x60, uint64(len(name)))
	instruction = append(instruction, name...)
	instruction = append(instruction, pref(7, 0x80, uint64(len(value)))...)
	instruction = append(instruction, value...)
	process(t, d, instruction)
	fields, err := d.Decode(context.Background(), 0, []byte{2, 0, 0x80}, 128, nil)
	require.NoError(t, err)
	require.Equal(t, []base.HeaderField{{Name: "custom-key", Value: "custom-value"}}, fields)
}
func TestBlockedDecodeCancellationAndLimit(t *testing.T) {
	var mu sync.Mutex
	var feedback []byte
	d := dynamic.NewDecoder(128, 1, func(b []byte) error { mu.Lock(); defer mu.Unlock(); feedback = append(feedback, b...); return nil })
	waiting := make(chan struct{})
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_, err := d.Decode(ctx, 8, []byte{2, 0, 0x80}, 100, func(ctx context.Context, ready <-chan struct{}) error {
			close(waiting)
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case <-ready:
				return nil
			}
		})
		done <- err
	}()
	<-waiting
	_, err := d.Decode(context.Background(), 12, []byte{2, 0, 0x80}, 100, nil)
	require.ErrorIs(t, err, dynamic.ErrDecompression)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	require.NoError(t, d.Cancel(8))
	mu.Lock()
	require.Equal(t, []byte{0x48}, feedback)
	mu.Unlock()
	// The cancelled stream released its blocking allowance.
	waiting = make(chan struct{})
	var fields []base.HeaderField
	go func() {
		var err error
		fields, err = d.Decode(context.Background(), 12, []byte{2, 0, 0x80}, 100, func(ctx context.Context, ready <-chan struct{}) error {
			select {
			case <-waiting:
			default:
				close(waiting)
			}
			<-ready
			return nil
		})
		done <- err
	}()
	<-waiting
	process(t, d, append(pref(5, 0x20, 128), literal("x", "v")...))
	require.NoError(t, <-done)
	require.Equal(t, []base.HeaderField{{Name: "x", Value: "v"}}, fields)
}
func TestDecoderCloseUnblocks(t *testing.T) {
	d := dynamic.NewDecoder(128, 1, nil)
	waiting := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := d.Decode(context.Background(), 0, []byte{2, 0, 0x80}, 100, func(ctx context.Context, ready <-chan struct{}) error { close(waiting); <-ready; return nil })
		done <- err
	}()
	<-waiting
	sentinel := errors.New("closed connection")
	d.Close(sentinel)
	require.ErrorIs(t, <-done, sentinel)
}
func TestRequiredInsertCountWrapAndEviction(t *testing.T) {
	d := dynamic.NewDecoder(64, 1, nil)
	process(t, d, pref(5, 0x20, 64))
	for i := 0; i < 10; i++ {
		process(t, d, literal("x", string(rune('a'+i))))
	}
	fields, err := d.Decode(context.Background(), 0, []byte{3, 0, 0x80}, 128, nil) // RIC=10 encoded modulo4+1 =3
	require.NoError(t, err)
	require.Equal(t, []base.HeaderField{{Name: "x", Value: "j"}}, fields)
	_, err = d.Decode(context.Background(), 0, []byte{3, 0, 0x81}, 128, nil)
	require.ErrorIs(t, err, dynamic.ErrDecompression)
}
func TestInvalidInstructionsAndBlocks(t *testing.T) {
	for name, instruction := range map[string][]byte{
		"capacity": pref(5, 0x20, 129), "insert-without-capacity": literal("x", "y"), "bad-static-name": {0xff, 0x7f, 0}, "missing-value": {0xc0}, "bad-duplicate": {0}, "truncated-int": {0x3f}, "overflow-int": {0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0},
	} {
		t.Run(name, func(t *testing.T) {
			d := dynamic.NewDecoder(128, 1, nil)
			require.ErrorIs(t, d.ReadEncoder(bytes.NewReader(instruction)), dynamic.ErrEncoderStream)
		})
	}
	for name, block := range map[string][]byte{
		"empty": {}, "missing-base": {0}, "invalid-wrap": {9, 0}, "negative-base": {1, 0x80}, "missing-reference": {2, 0}, "bad-static": {0, 0, 0xff, 0x7f}, "dynamic-with-zero-ric": {0, 0, 0x80}, "postbase-out-of-range": {2, 0, 0x10}, "truncated-literal": {0, 0, 0x21, 'a'}, "invalid-huffman": {0, 0, 0x28, 0x81, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			d := dynamic.NewDecoder(128, 1, nil)
			process(t, d, append(pref(5, 0x20, 128), literal("x", "v")...))
			_, err := d.Decode(context.Background(), 0, block, 1024, nil)
			require.ErrorIs(t, err, dynamic.ErrDecompression)
		})
	}
}
func TestDecodedSizeLimitAndFeedbackFailure(t *testing.T) {
	d := dynamic.NewDecoder(128, 1, nil)
	process(t, d, append(pref(5, 0x20, 128), literal("x", "1234567890")...))
	_, err := d.Decode(context.Background(), 0, []byte{2, 0, 0x80, 0x80}, 50, nil)
	require.ErrorIs(t, err, dynamic.ErrFieldSectionTooLarge)
	sentinel := errors.New("feedback backlog")
	d = dynamic.NewDecoder(128, 1, func([]byte) error { return sentinel })
	require.ErrorIs(t, d.ReadEncoder(bytes.NewReader(append(pref(5, 0x20, 128), literal("x", "v")...))), sentinel)
	_, err = d.Decode(context.Background(), 0, []byte{2, 0, 0x80}, 1024, nil)
	require.ErrorIs(t, err, sentinel)
}
func TestStaticEncoderFeedback(t *testing.T) {
	require.ErrorIs(t, dynamic.ReadDecoder(bytes.NewReader([]byte{0x40, 0x44})), io.EOF)
	for _, b := range [][]byte{{0x80}, {0}, {1}, {0x7f}, {0xff}} {
		require.ErrorIs(t, dynamic.ReadDecoder(bytes.NewReader(b)), dynamic.ErrDecoderStream)
	}
}

type byteReader struct{ io.Reader }

func (r byteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}
func TestFragmentedInstructions(t *testing.T) {
	d := dynamic.NewDecoder(128, 1, nil)
	b := append(pref(5, 0x20, 128), literal("custom", "fragmented")...)
	require.ErrorIs(t, d.ReadEncoder(byteReader{bytes.NewReader(b)}), io.EOF)
	fields, err := d.Decode(context.Background(), 0, []byte{2, 0, 0x80}, 256, nil)
	require.NoError(t, err)
	require.Equal(t, "fragmented", fields[0].Value)
}
func FuzzDecoder(f *testing.F) {
	f.Add([]byte{2, 0, 0x80})
	f.Add([]byte{0, 0, 0xd9})
	f.Add([]byte{2, 0x80, 0x10})
	f.Fuzz(func(t *testing.T, block []byte) {
		d := dynamic.NewDecoder(128, 0, nil)
		_ = d.ReadEncoder(bytes.NewReader(append(pref(5, 0x20, 128), literal("x", "v")...)))
		_, _ = d.Decode(context.Background(), 0, slices.Clone(block), 512, nil)
	})
}

func FuzzEncoderInstructions(f *testing.F) {
	f.Add(append(pref(5, 0x20, 128), literal("x", "v")...))
	f.Add([]byte{0x3f, 0xff, 0xff})
	f.Add([]byte{0xff, 0x7f, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		d := dynamic.NewDecoder(128, 0, nil)
		_ = d.ReadEncoder(bytes.NewReader(input))
		_ = dynamic.ReadDecoder(bytes.NewReader(input))
	})
}
