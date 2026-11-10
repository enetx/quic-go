package qpack_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"testing"

	codec "github.com/enetx/quic-go/internal/qpack"
	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func configured(t *testing.T, options codec.EncoderOptions, maximum, capacity, blocked uint64) *codec.Encoder {
	t.Helper()
	e := codec.NewEncoder(options)
	require.NoError(t, e.Configure(maximum, capacity, blocked))
	return e
}

func feedback(t *testing.T, e *codec.Encoder, data ...byte) {
	t.Helper()
	require.ErrorIs(t, e.ReadDecoder(bytes.NewReader(data)), io.EOF)
}

func encode(t *testing.T, e *codec.Encoder, id uint64, fields ...codec.Field) ([]byte, []byte) {
	t.Helper()
	var instructions []byte
	block, err := e.Encode(id, fields, func(b []byte) error { instructions = append(instructions, b...); return nil })
	require.NoError(t, err)
	return block, instructions
}

func TestEncoderStaticCompatibility(t *testing.T) {
	e := codec.NewEncoder(codec.EncoderOptions{})
	fields := []codec.Field{{Name: "x-unknown", Value: "value"}, {Name: ":path", Value: "/custom"}, {Name: "sec-ch-ua-mobile", Value: "?0"}, {Name: "content-type", Value: "application/custom"}, {Name: "cookie", Value: ""}}
	// Every exact official static-table entry, followed by non-exact names/values.
	for i := 0; i < 99; i++ {
		encoded := []byte{0, 0, byte(0xc0 | min(i, 63))}
		if i >= 63 {
			encoded = append(encoded, byte(i-63))
		}
		f, err := base.NewDecoder().Decode(encoded)()
		require.NoError(t, err)
		fields = append(fields, codec.Field{Name: f.Name, Value: f.Value})
	}
	var want bytes.Buffer
	native := base.NewEncoder(&want)
	for _, f := range fields {
		require.NoError(t, native.WriteField(base.HeaderField{Name: f.Name, Value: f.Value}))
	}
	got, _ := encode(t, e, 0, fields...)
	require.Equal(t, want.Bytes(), got)
}

func TestEncoderIndependentWireVectors(t *testing.T) {
	// Two static-name insertions and two dynamic references, with raw strings.
	// Integers and representations follow RFC 9204 4.3/4.5 independently of Decode.
	for _, postBase := range []bool{false, true} {
		t.Run(fmt.Sprint(postBase), func(t *testing.T) {
			e := configured(t, codec.EncoderOptions{DynamicTable: true, Huffman: codec.HuffmanNever, PostBaseReferences: postBase}, 220, 220, 2)
			block, instructions := encode(t, e, 0, codec.Field{Name: ":authority", Value: "www.example.com"}, codec.Field{Name: ":path", Value: "/sample/path"})
			wantInstructions := append([]byte{0xc0, 15}, []byte("www.example.com")...)
			wantInstructions = append(wantInstructions, 0xc1, 12)
			wantInstructions = append(wantInstructions, []byte("/sample/path")...)
			require.Equal(t, wantInstructions, instructions)
			want := []byte{3, 0, 0x81, 0x80}
			if postBase {
				want = []byte{3, 0x81, 0x10, 0x11}
			}
			require.Equal(t, want, block)
		})
	}
}

func TestEncoderRoundTripEvictionAndRICWrap(t *testing.T) {
	for _, postBase := range []bool{false, true} {
		for _, maximum := range []uint64{128, 65536} {
			t.Run(fmt.Sprintf("post=%t/max=%d", postBase, maximum), func(t *testing.T) {
				e := configured(t, codec.EncoderOptions{DynamicTable: true, Huffman: codec.HuffmanAuto, PostBaseReferences: postBase}, maximum, 128, 4)
				var replies bytes.Buffer
				d := codec.NewDecoder(maximum, 4, func(b []byte) error { _, err := replies.Write(b); return err })
				require.ErrorIs(t, d.ReadEncoder(bytes.NewReader(codec.AppendEncoderCapacity(nil, 128))), io.EOF)
				for i := 0; i < 200; i++ {
					fields := []codec.Field{{Name: ":method", Value: "GET"}, {Name: fmt.Sprintf("x-%03d", i), Value: "repeated value"}}
					block, instructions := encode(t, e, uint64(4*i), fields...)
					require.NotEmpty(t, instructions, "table stopped making progress at %d", i)
					require.ErrorIs(t, d.ReadEncoder(bytes.NewReader(instructions)), io.EOF)
					got, err := d.Decode(context.Background(), uint64(4*i), block, 1<<20, nil)
					require.NoError(t, err, "section %d, block %x", i, block)
					require.Equal(t, []base.HeaderField{{Name: fields[0].Name, Value: fields[0].Value}, {Name: fields[1].Name, Value: fields[1].Value}}, got)
					feedback(t, e, replies.Bytes()...)
					replies.Reset()
				}
			})
		}
	}
}

func TestEncoderBlockedStreamBudget(t *testing.T) {
	for _, budget := range []uint64{0, 1, 2} {
		t.Run(fmt.Sprint(budget), func(t *testing.T) {
			e := configured(t, codec.EncoderOptions{DynamicTable: true}, 4096, 4096, budget)
			blocked := uint64(0)
			for i := uint64(0); i < 10; i++ {
				block, _ := encode(t, e, 4*i, codec.Field{Name: "user-agent", Value: "audit-agent"})
				if block[0] != 0 {
					blocked++
				}
			}
			require.Equal(t, budget, blocked)
			if budget > 0 {
				feedback(t, e, 0x80) // Acknowledging stream 0 advances the Known Received Count.
				block, _ := encode(t, e, 40, codec.Field{Name: "user-agent", Value: "audit-agent"})
				require.NotZero(t, block[0]) // Already acknowledged references do not consume the budget.
			}
		})
	}
}

func TestEncoderRetainsOutstandingAndUnacknowledgedEntries(t *testing.T) {
	for _, acknowledgeInsert := range []bool{false, true} {
		t.Run(fmt.Sprint(acknowledgeInsert), func(t *testing.T) {
			e := configured(t, codec.EncoderOptions{DynamicTable: true}, 64, 64, 8)
			first := codec.Field{Name: "user-agent", Value: "audit-agent"}
			block, _ := encode(t, e, 0, first)
			require.NotZero(t, block[0])
			if acknowledgeInsert {
				feedback(t, e, 1)
			}
			_, instructions := encode(t, e, 4, codec.Field{Name: "x-new", Value: "replacement"})
			require.Empty(t, instructions, "entry is still referenced by stream 0")
			feedback(t, e, 0x40) // Cancellation releases references, without acknowledging insertion.
			_, instructions = encode(t, e, 8, codec.Field{Name: "x-new", Value: "replacement"})
			if !acknowledgeInsert {
				require.Empty(t, instructions, "unacknowledged entry must remain even after cancellation")
				feedback(t, e, 1)
				_, instructions = encode(t, e, 12, codec.Field{Name: "x-new", Value: "replacement"})
			}
			require.NotEmpty(t, instructions, "acknowledged unreferenced entry should be evictable")
		})
	}
}

func TestEncoderMaximumCapacityRIC(t *testing.T) {
	e := configured(t, codec.EncoderOptions{DynamicTable: true}, 4096, 64, 1)
	var field codec.Field
	for i := uint64(0); i < 5; i++ {
		field = codec.Field{Name: fmt.Sprintf("x-%d", i), Value: "a"}
		block, _ := encode(t, e, i*4, field)
		require.NotZero(t, block[0])
		feedback(t, e, byte(0x80|i*4))
	}
	block, _ := encode(t, e, 20, field)
	require.Equal(t, byte(6), block[0], "RIC modulo uses the peer's maximum, not chosen capacity")
}

func TestEncoderFIFOSectionsAndCancellation(t *testing.T) {
	e := configured(t, codec.EncoderOptions{DynamicTable: true, MaxTrackedSections: 2}, 4096, 4096, 1)
	for _, value := range []string{"first", "trailer"} {
		block, _ := encode(t, e, 0, codec.Field{Name: "user-agent", Value: value})
		require.NotZero(t, block[0], "same blocked stream may carry multiple sections")
	}
	block, _ := encode(t, e, 4, codec.Field{Name: "user-agent", Value: "first"})
	require.Zero(t, block[0], "tracking limit must force static fallback")
	feedback(t, e, 0x80) // Only the first section is acknowledged.
	block, _ = encode(t, e, 4, codec.Field{Name: "user-agent", Value: "trailer"})
	require.Zero(t, block[0], "second section still consumes the one blocked-stream slot")
	feedback(t, e, 0x80)
	block, _ = encode(t, e, 4, codec.Field{Name: "user-agent", Value: "trailer"})
	require.NotZero(t, block[0])
	feedback(t, e, 0x44) // Releases all sections on stream 4.
	require.ErrorIs(t, e.ReadDecoder(bytes.NewReader([]byte{0x84})), codec.ErrDecoderStream)
	feedback(t, e, 0x44) // Cancelling an unreferenced stream is valid.
}

func TestEncoderInstructionBackpressureRollback(t *testing.T) {
	e := configured(t, codec.EncoderOptions{DynamicTable: true}, 4096, 4096, 1)
	fields := []codec.Field{{Name: "x-new", Value: "value"}}
	blocked, err := e.Encode(0, fields, func([]byte) error { return codec.ErrEncoderBlocked })
	require.NoError(t, err)
	require.Zero(t, blocked[0])
	// A failed insertion cannot be acknowledged: it must not exist in the state.
	require.ErrorIs(t, e.ReadDecoder(bytes.NewReader([]byte{1})), codec.ErrDecoderStream)
	block, instructions := encode(t, e, 4, fields...)
	require.NotEmpty(t, instructions)
	require.Equal(t, byte(2), block[0], "first accepted insertion must still have absolute index 0")
	wantErr := errors.New("connection closed")
	_, err = e.Encode(8, []codec.Field{{Name: "x-second", Value: "value"}}, func([]byte) error { return wantErr })
	// Stream 4 is blocked; allow its insertion to become acknowledged first.
	if err == nil {
		feedback(t, e, 0x84)
		_, err = e.Encode(12, []codec.Field{{Name: "x-second", Value: "value"}}, func([]byte) error { return wantErr })
	}
	require.ErrorIs(t, err, wantErr)
}

func TestEncoderRollbackDoesNotPinExistingEntries(t *testing.T) {
	e := configured(t, codec.EncoderOptions{DynamicTable: true}, 128, 128, 4)
	first := codec.Field{Name: "x-first", Value: "a"}
	encode(t, e, 0, first)
	feedback(t, e, 0x80)
	block, err := e.Encode(4, []codec.Field{first, {Name: "x-second", Value: "b"}}, func([]byte) error { return codec.ErrEncoderBlocked })
	require.NoError(t, err)
	require.Zero(t, block[0])
	// This insertion must evict the first entry. A leaked reference from the
	// rejected transaction would incorrectly pin it and prevent progress.
	_, instructions := encode(t, e, 8, codec.Field{Name: "x-large", Value: strings.Repeat("a", 70)})
	require.NotEmpty(t, instructions)
	feedback(t, e, 0x88)
	_, instructions = encode(t, e, 12, codec.Field{Name: "x-new", Value: "c"})
	require.NotEmpty(t, instructions)
}

func TestEncoderRetainsReferencesInsideCurrentSection(t *testing.T) {
	e := configured(t, codec.EncoderOptions{DynamicTable: true}, 64, 64, 4)
	first := codec.Field{Name: "x-first", Value: "a"}
	encode(t, e, 0, first)
	feedback(t, e, 0x80)
	block, instructions := encode(t, e, 4, first, codec.Field{Name: "x-second", Value: "b"})
	require.NotZero(t, block[0])
	require.Empty(t, instructions, "later fields cannot evict an entry already referenced in this section")
	feedback(t, e, 0x84)
	_, instructions = encode(t, e, 8, codec.Field{Name: "x-second", Value: "b"})
	require.NotEmpty(t, instructions, "entry becomes evictable after its section ACK")
}

func TestEncoderNeverIndexAndHuffmanVectors(t *testing.T) {
	for _, tc := range []struct {
		mode     codec.HuffmanMode
		expected string
	}{
		{codec.HuffmanDefault, "00007f4582ff01"},
		{codec.HuffmanAlways, "00007f4582ff01"},
		{codec.HuffmanAuto, "00007f45023f30"},
		{codec.HuffmanNever, "00007f45023f30"},
	} {
		t.Run(fmt.Sprint(tc.mode), func(t *testing.T) {
			e := configured(t, codec.EncoderOptions{DynamicTable: true, Huffman: tc.mode}, 4096, 4096, 1)
			field := codec.Field{Name: "authorization", Value: "?0", NeverIndex: true}
			block, instructions := encode(t, e, 0, field)
			require.Empty(t, instructions)
			// Index 84 (Authorization) requires extension 69 in its four-bit prefix.
			require.Equal(t, tc.expected, hex.EncodeToString(block))
			exact, instructions := encode(t, e, 4, codec.Field{Name: "accept-encoding", Value: "gzip, deflate, br", NeverIndex: true})
			require.Empty(t, instructions, "even an exact static match must remain never indexed")
			require.Equal(t, byte(0x70), exact[2]&0xf0, "an exact static match must become an N=1 literal")
		})
	}
}

func TestEncoderPolicyNewNamesAndLiteralInsertions(t *testing.T) {
	e := configured(t, codec.EncoderOptions{DynamicTable: true, Indexing: codec.IndexNewNames, LiteralInsertNames: true, PostBaseReferences: true}, 4096, 4096, 4)
	fields := []codec.Field{{Name: "user-agent", Value: "agent"}, {Name: "x-new", Value: "first"}}
	_, instructions := encode(t, e, 0, fields...)
	require.Equal(t, byte(0x40), instructions[0]&0xc0)
	feedback(t, e, 0x80)
	fields[1].Value = "second"
	block, instructions := encode(t, e, 4, fields...)
	require.Empty(t, instructions, "an existing name must use a literal value, without reinsertion")
	require.NotZero(t, block[0], "dynamic name should still be referenced")
	policy := configured(t, codec.EncoderOptions{DynamicTable: true, IndexingPolicy: func(name, value string) bool { return name != "x-private" }}, 4096, 4096, 4)
	_, instructions = encode(t, policy, 0, codec.Field{Name: "x-private", Value: "secret"})
	require.Empty(t, instructions)
}

func TestEncoderInsertionFailurePolicy(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(fmt.Sprint(stop), func(t *testing.T) {
			e := configured(t, codec.EncoderOptions{DynamicTable: true, StopOnInsertionFailure: stop}, 128, 128, 1)
			block, instructions := encode(t, e, 0, codec.Field{Name: "x-large", Value: strings.Repeat("a", 256)}, codec.Field{Name: "x-small", Value: "fits"})
			if stop {
				require.Empty(t, instructions)
				require.Zero(t, block[0])
			} else {
				require.NotEmpty(t, instructions)
				require.NotZero(t, block[0])
			}
		})
	}
}

func TestEncoderFeedbackErrorsAndFragmentation(t *testing.T) {
	for _, data := range [][]byte{{0}, {1}, {0x80}, {0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}} {
		e := codec.NewEncoder(codec.EncoderOptions{})
		require.ErrorIs(t, e.ReadDecoder(bytes.NewReader(data)), codec.ErrDecoderStream)
	}
	e := configured(t, codec.EncoderOptions{DynamicTable: true}, 4096, 4096, 1)
	encode(t, e, 1024, codec.Field{Name: "x-new", Value: "first"})
	r, w := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- e.ReadDecoder(r) }()
	// Stream 1024 section ACK: prefix 127, continuation 897 = 0x81 0x07.
	for _, b := range []byte{0xff, 0x81, 0x07} {
		_, err := w.Write([]byte{b})
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	require.ErrorIs(t, <-done, io.EOF)
	require.NoError(t, r.Close())
	feedback(t, e, 0x40)
}

func TestEncoderConcurrentSections(t *testing.T) {
	e := configured(t, codec.EncoderOptions{DynamicTable: true}, 4096, 4096, 2)
	var wg sync.WaitGroup
	for i := uint64(0); i < 100; i++ {
		wg.Go(func() {
			block, err := e.Encode(i*4, []codec.Field{{Name: "user-agent", Value: "shared"}}, func([]byte) error { return nil })
			require.NoError(t, err)
			if block[0] != 0 {
				// Each goroutine owns this section's feedback. Both ACK/cancel race safely with Encode.
				var instruction []byte
				mask, flag := uint64(63), byte(0x40)
				if i%2 == 0 {
					mask, flag = 127, 0x80
				}
				if i*4 < mask {
					instruction = []byte{flag | byte(i*4)}
				} else {
					v := i*4 - mask
					instruction = []byte{flag | byte(mask)}
					for v >= 128 {
						instruction = append(instruction, byte(v&127)|0x80)
						v >>= 7
					}
					instruction = append(instruction, byte(v))
				}
				require.ErrorIs(t, e.ReadDecoder(bytes.NewReader(instruction)), io.EOF)
			}
		})
	}
	wg.Wait()
}

func TestEncoderDrainingDuplicate(t *testing.T) {
	e := configured(t, codec.EncoderOptions{DynamicTable: true, DrainingFraction: .5, Huffman: codec.HuffmanNever}, 128, 128, 4)
	first := codec.Field{Name: "x-a", Value: "a"}
	encode(t, e, 0, first)
	feedback(t, e, 0x80)
	encode(t, e, 4, codec.Field{Name: "x-b", Value: "b"})
	feedback(t, e, 0x84)
	block, instructions := encode(t, e, 8, first)
	require.Equal(t, []byte{1}, instructions, "duplicate the draining oldest entry at relative index 1")
	require.Equal(t, []byte{4, 0, 0x80}, block)
}

func TestEncoderLimitsAndValidation(t *testing.T) {
	for _, options := range []codec.EncoderOptions{{Huffman: 4}, {Indexing: 3}, {DrainingFraction: -1}, {DrainingFraction: 1.1}, {DrainingFraction: math.NaN()}, {DrainingFraction: math.Inf(1)}, {MaxTrackedSections: 1 << 62}} {
		require.Error(t, options.Validate())
	}
	e := codec.NewEncoder(codec.EncoderOptions{})
	require.Error(t, e.Configure(1<<62, 0, 0))
	require.Error(t, e.Configure(100, 101, 0))
	require.NoError(t, e.Configure(100, 64, 1))
	require.NoError(t, e.Configure(100, 64, 1))
	require.Error(t, e.Configure(100, 65, 1))
	_, err := e.Encode(1<<62, nil, nil)
	require.Error(t, err)
	for _, capacity := range []uint64{0, 1, 31} {
		e = configured(t, codec.EncoderOptions{DynamicTable: true}, 4096, capacity, 2)
		block, instructions := encode(t, e, 0, codec.Field{Name: "x-big", Value: strings.Repeat("a", 128)})
		require.Empty(t, instructions)
		require.Zero(t, block[0])
	}
}
