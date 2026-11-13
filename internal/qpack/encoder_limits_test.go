package qpack

import (
	"reflect"
	"slices"
	"testing"
)

func TestUpdateRememberedPeerLimitsRetainsDynamicState(t *testing.T) {
	e := NewEncoder(EncoderOptions{DynamicTable: true})
	if err := e.Configure(4096, 4096, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Encode(0, []Field{{Name: "x-shared", Value: "reused"}}, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	before := e.state
	before.table = slices.Clone(e.state.table)
	if len(before.table) != 1 || before.tracked == 0 {
		t.Fatal("test must retain a referenced dynamic entry")
	}
	if err := e.UpdatePeerLimits(4096, 4096, 4); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, e.state) {
		t.Fatal("compatible settings update reset table entries or outstanding references")
	}
	if _, err := e.Encode(4, []Field{{Name: "x-shared", Value: "reused"}}, func([]byte) error { t.Fatal("existing entry must be reused without a new insertion"); return nil }); err != nil {
		t.Fatal(err)
	}
	for _, values := range [][3]uint64{{8192, 4096, 4}, {2048, 2048, 4}, {4096, 1024, 4}, {4096, 4096, 1}} {
		if err := e.UpdatePeerLimits(values[0], values[1], values[2]); err == nil {
			t.Fatalf("accepted incompatible update %v", values)
		}
	}
}

func TestUpdateRememberedZeroCapacity(t *testing.T) {
	e := NewEncoder(EncoderOptions{DynamicTable: true})
	if err := e.Configure(0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := e.UpdatePeerLimits(4096, 1024, 16); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Encode(0, []Field{{Name: "x", Value: "value"}}, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if e.state.inserted != 1 {
		t.Fatal("newly enabled capacity must permit insertion")
	}
}
