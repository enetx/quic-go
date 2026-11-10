package qpack_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"

	codec "github.com/enetx/quic-go/internal/qpack"
	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func FuzzEncoderRoundTrip(f *testing.F) {
	f.Add([]byte("repeated headers and changed credentials"), uint8(0), false)
	f.Add([]byte{0, 255, 1, 128, 32, 127, 127, 1, 0}, uint8(1), true)
	f.Add([]byte("cookie=a=1; b=2\x00authorization=secret"), uint8(2), false)
	f.Fuzz(func(t *testing.T, data []byte, mode uint8, postBase bool) {
		if len(data) == 0 || len(data) > 256 {
			t.Skip()
		}
		capacity := uint64(128 + int(data[0])*16)
		e := configured(t, codec.EncoderOptions{DynamicTable: true, Huffman: codec.HuffmanMode(mode % 4), PostBaseReferences: postBase,
			DrainingFraction: float64(data[0]%4) / 4, Indexing: codec.IndexingMode(data[0] % 3), LiteralInsertNames: data[0]&1 != 0}, 65536, capacity, 4)
		var instructions, replies bytes.Buffer
		d := codec.NewDecoder(65536, 4, func(b []byte) error { _, err := replies.Write(b); return err })
		require.ErrorIs(t, d.ReadEncoder(bytes.NewReader(codec.AppendEncoderCapacity(nil, capacity))), io.EOF)
		for i := 0; i < len(data); i++ {
			value := string(data[max(0, i-12) : i+1])
			fields := []codec.Field{{Name: ":method", Value: "GET"}, {Name: fmt.Sprintf("x-%d", data[i]%8), Value: value, NeverIndex: data[i]&16 != 0}}
			instructions.Reset()
			block, err := e.Encode(uint64(i*4), fields, func(b []byte) error { _, err := instructions.Write(b); return err })
			require.NoError(t, err)
			require.ErrorIs(t, d.ReadEncoder(bytes.NewReader(instructions.Bytes())), io.EOF)
			got, err := d.Decode(context.Background(), uint64(i*4), block, 1<<20, nil)
			require.NoError(t, err)
			require.Equal(t, []base.HeaderField{{Name: fields[0].Name, Value: fields[0].Value}, {Name: fields[1].Name, Value: fields[1].Value}}, got)
			feedback(t, e, replies.Bytes()...)
			replies.Reset()
		}
	})
}

func FuzzEncoderFeedback(f *testing.F) {
	for _, seed := range [][]byte{{0x80}, {1, 0x80}, {0x40}, {0xff, 0x81, 7}, {0x3f, 0xff, 0xff, 0xff}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1024 {
			t.Skip()
		}
		e := configured(t, codec.EncoderOptions{DynamicTable: true}, 4096, 4096, 4)
		for i := range 4 {
			encode(t, e, uint64(i*4), codec.Field{Name: fmt.Sprintf("x-%d", i), Value: "value"})
		}
		// Complete, partial, overlong and out-of-order instructions must terminate
		// with a classified error or EOF, never overflow counters or panic.
		e.ReadDecoder(bytes.NewReader(data))
	})
}
