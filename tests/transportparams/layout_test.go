package transportparams_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/quic-go/transportparams"
)

func encode(pairs ...transportparams.Parameter) []byte {
	var b []byte
	for _, p := range pairs {
		b = quicvarint.Append(b, p.ID)
		b = quicvarint.Append(b, uint64(len(p.Value)))
		b = append(b, p.Value...)
	}
	return b
}
func TestLayout(t *testing.T) {
	input := encode(transportparams.Parameter{ID: 27, Value: []byte{9}}, transportparams.Parameter{ID: 5, Value: []byte{4}}, transportparams.Parameter{ID: 15, Value: []byte{1, 2, 3}}, transportparams.Parameter{ID: 4, Value: []byte{7}})
	original := bytes.Clone(input)
	l := &transportparams.Layout{Order: []uint64{15, 0x3128, transportparams.Grease, 5}, Additional: []transportparams.Parameter{{ID: 0x3128, Value: []byte("TEST")}}}
	if err := l.Validate(); err != nil {
		t.Fatal(err)
	}
	got := l.Apply(input)
	want := encode(transportparams.Parameter{ID: 15, Value: []byte{1, 2, 3}}, transportparams.Parameter{ID: 0x3128, Value: []byte("TEST")}, transportparams.Parameter{ID: 27, Value: []byte{9}}, transportparams.Parameter{ID: 5, Value: []byte{4}}, transportparams.Parameter{ID: 4, Value: []byte{7}})
	if !bytes.Equal(got, want) || !bytes.Equal(input, original) {
		t.Fatalf("got %x, want %x; input=%x", got, want, input)
	}
	clone := l.Clone()
	l.Order[0] = 4
	l.Additional[0].Value[0] = 'X'
	if !bytes.Equal(clone.Apply(input), want) {
		t.Fatal("snapshot mutated")
	}
	clone.DisableGrease = true
	expected := encode(transportparams.Parameter{ID: 15, Value: []byte{1, 2, 3}}, transportparams.Parameter{ID: 0x3128, Value: []byte("TEST")}, transportparams.Parameter{ID: 5, Value: []byte{4}}, transportparams.Parameter{ID: 4, Value: []byte{7}})
	if !bytes.Equal(clone.Apply(input), expected) {
		t.Fatal("GREASE was not removed")
	}
	if got := (*transportparams.Layout)(nil).Apply(input); !slices.Equal(got, input) {
		t.Fatal("native encoding changed")
	}
}
func TestExternalGreaseParameter(t *testing.T) {
	layout := &transportparams.Layout{DisableGrease: true, Order: []uint64{58, 4}, Additional: []transportparams.Parameter{{ID: 58, Value: []byte{1, 2}}}}
	if err := layout.Validate(); err != nil {
		t.Fatal(err)
	}
	got := layout.Apply(encode(transportparams.Parameter{ID: 27, Value: []byte{9}}, transportparams.Parameter{ID: 4, Value: []byte{7}}))
	want := encode(transportparams.Parameter{ID: 58, Value: []byte{1, 2}}, transportparams.Parameter{ID: 4, Value: []byte{7}})
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestLayoutValidation(t *testing.T) {
	for name, l := range map[string]*transportparams.Layout{
		"duplicate-order": {Order: []uint64{5, 5}}, "large-order": {Order: []uint64{1 << 63}},
		"engine-field": {Additional: []transportparams.Parameter{{ID: 5}}}, "server-field": {Additional: []transportparams.Parameter{{ID: 0}}},
		"duplicate-extra": {Additional: []transportparams.Parameter{{ID: 100}, {ID: 100}}}, "large-extra": {Additional: []transportparams.Parameter{{ID: 1 << 63}}},
		"reserved-extra":       {Additional: []transportparams.Parameter{{ID: 27}}},
		"legacy-ack-frequency": {DisableGrease: true, Additional: []transportparams.Parameter{{ID: 0xff02de1a, Value: []byte{0x43, 0xe8}}}},
		"ack-frequency":        {Additional: []transportparams.Parameter{{ID: 0xff04de1b}}},
	} {
		t.Run(name, func(t *testing.T) {
			if l.Validate() == nil {
				t.Fatal("invalid layout accepted")
			}
		})
	}
}
