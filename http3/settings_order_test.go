package http3

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/quic-go/quicvarint"
)

func TestRuntimeDatagramsKeepExplicitSettingPosition(t *testing.T) {
	settings := g.NewMapOrd[uint64, uint64]()
	settings.Insert(7, 0)
	settings.Insert(settingDatagram, 1)
	settings.Insert(1, 0)
	before := settings.Clone()
	frame := initialClientSettings(true, settings)
	parsed := roundTripSettings(t, frame)
	if !parsed.Datagram {
		t.Fatal("datagram setting missing")
	}
	r := bytes.NewReader(frame.Append(nil))
	if typ, err := quicvarint.Read(r); err != nil || typ != 4 {
		t.Fatalf("type = %d, %v", typ, err)
	}
	length, err := quicvarint.Read(r)
	if err != nil || int(length) != r.Len() {
		t.Fatalf("length = %d, %v", length, err)
	}
	var ids []uint64
	for r.Len() > 0 {
		id, err := quicvarint.Read(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := quicvarint.Read(r); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if !reflect.DeepEqual(ids, []uint64{7, settingDatagram, 1}) {
		t.Fatalf("setting order = %v", ids)
	}
	if !reflect.DeepEqual(settings, before) {
		t.Fatal("input settings mutated")
	}
	if !roundTripSettings(t, initialClientSettings(true, nil)).Datagram {
		t.Fatal("implicit datagram setting missing")
	}
}
