package http3

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/quic-go"
)

func roundTripSettings(t *testing.T, sf *settingsFrame) *settingsFrame {
	t.Helper()
	data := sf.Append(nil)
	fp := &frameParser{
		r:         bytes.NewReader(data),
		streamID:  0,
		closeConn: func(quic.ApplicationErrorCode, string) error { return nil },
	}
	f, err := fp.ParseNext(nil)
	if err != nil {
		t.Fatalf("ParseNext: %v", err)
	}
	parsed, ok := f.(*settingsFrame)
	if !ok {
		t.Fatalf("expected *settingsFrame, got %T", f)
	}
	return parsed
}

// Our fork only emits SETTINGS_MAX_FIELD_SECTION_SIZE when the value is > 0.
// A value of 0 must NOT be written, so it round-trips back as "absent" (-1).
func TestMaxFieldSectionSize_ZeroNotEmitted(t *testing.T) {
	parsed := roundTripSettings(t, &settingsFrame{MaxFieldSectionSize: 0})
	if parsed.MaxFieldSectionSize != -1 {
		t.Fatalf("MaxFieldSectionSize=0 should not be emitted; parsed=%d, want -1", parsed.MaxFieldSectionSize)
	}

	// And the encoded frame must be strictly smaller than one that carries the setting.
	withZero := (&settingsFrame{MaxFieldSectionSize: 0}).Append(nil)
	withVal := (&settingsFrame{MaxFieldSectionSize: 100}).Append(nil)
	if len(withVal) <= len(withZero) {
		t.Fatalf("expected the frame with MaxFieldSectionSize=100 to be larger; zero=%d val=%d", len(withZero), len(withVal))
	}
}

// A positive SETTINGS_MAX_FIELD_SECTION_SIZE must be emitted and round-trip intact.
func TestMaxFieldSectionSize_PositiveRoundTrips(t *testing.T) {
	parsed := roundTripSettings(t, &settingsFrame{MaxFieldSectionSize: 12345})
	if parsed.MaxFieldSectionSize != 12345 {
		t.Fatalf("MaxFieldSectionSize round-trip mismatch: got %d, want 12345", parsed.MaxFieldSectionSize)
	}
}

// The "Other" settings use g.MapOrd and must preserve insertion order on the wire.
func TestOtherSettings_PreserveOrder(t *testing.T) {
	other := g.NewMapOrd[uint64, uint64]()
	other.Insert(0x4a, 100)
	other.Insert(0x21, 200)
	other.Insert(0x55, 300)

	parsed := roundTripSettings(t, &settingsFrame{MaxFieldSectionSize: -1, Other: other})

	type pair struct{ k, v uint64 }
	var got []pair
	for k, v := range parsed.Other.Iter() {
		got = append(got, pair{k, v})
	}
	want := []pair{{0x4a, 100}, {0x21, 200}, {0x55, 300}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Other settings order mismatch:\n got=%v\nwant=%v", got, want)
	}
}

// Sanity: the recognized boolean settings still round-trip after the g.MapOrd change.
func TestDatagramAndExtendedConnectRoundTrip(t *testing.T) {
	parsed := roundTripSettings(t, &settingsFrame{
		MaxFieldSectionSize: -1,
		Datagram:            true,
		ExtendedConnect:     true,
	})
	if !parsed.Datagram {
		t.Error("Datagram setting did not round-trip")
	}
	if !parsed.ExtendedConnect {
		t.Error("ExtendedConnect setting did not round-trip")
	}
}

// Omitting our own zero setting must not reject a peer that explicitly sends it.
func TestMaxFieldSectionSize_ExplicitPeerZero(t *testing.T) {
	fp := frameParser{r: bytes.NewReader([]byte{0x4, 0x2, 0x6, 0x0})}
	frame, err := fp.ParseNext(nil)
	if err != nil {
		t.Fatal(err)
	}
	sf, ok := frame.(*settingsFrame)
	if !ok {
		t.Fatalf("expected SETTINGS, got %T", frame)
	}
	if sf.MaxFieldSectionSize != 0 {
		t.Fatalf("explicit peer zero parsed as %d", sf.MaxFieldSectionSize)
	}
}
