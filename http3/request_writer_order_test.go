package http3

import (
	"strings"
	"testing"

	"github.com/enetx/http"
	httpcommon "github.com/enetx/http/headerorder"
	"github.com/enetx/quic-go/http3/qlog"
)

func fieldNames(fields []qlog.HeaderField) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = f.Name
	}
	return out
}

// indexOf returns the position of the first field with the given (lowercased) name, or -1.
func indexOf(names []string, name string) int {
	for i, n := range names {
		if n == name {
			return i
		}
	}
	return -1
}

// assertSubsequence checks that want appears in names in the given relative order.
func assertSubsequence(t *testing.T, names, want []string) {
	t.Helper()
	prev := -1
	for _, w := range want {
		idx := indexOf(names, w)
		if idx < 0 {
			t.Fatalf("expected header %q not found in %v", w, names)
		}
		if idx <= prev {
			t.Fatalf("header %q out of order in %v (want order %v)", w, names, want)
		}
		prev = idx
	}
}

func encode(t *testing.T, req *http.Request, trailers string) []string {
	t.Helper()
	w := newRequestWriter()
	fields, err := w.encodeHeaders(req, false, trailers, 0, true)
	if err != nil {
		t.Fatalf("encodeHeaders: %v", err)
	}
	return fieldNames(fields)
}

// PHeader-Order: must control the order of pseudo-headers on the wire.
func TestPseudoHeaderOrder_Custom(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/path?q=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header[httpcommon.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}

	names := encode(t, req, "")
	assertSubsequence(t, names, []string{":method", ":authority", ":scheme", ":path"})
}

// Without PHeader-Order: the default pseudo-header order must be used.
func TestPseudoHeaderOrder_Default(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	names := encode(t, req, "")
	assertSubsequence(t, names, []string{":authority", ":method", ":path", ":scheme"})
}

// Header-Order: must control the order of regular headers on the wire.
func TestRegularHeaderOrder_Custom(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["X-A"] = []string{"1"}
	req.Header["X-B"] = []string{"2"}
	req.Header["X-C"] = []string{"3"}
	req.Header[httpcommon.HeaderOrderKey] = []string{"x-c", "x-a", "x-b"}

	names := encode(t, req, "")
	assertSubsequence(t, names, []string{"x-c", "x-a", "x-b"})
}

// Without Header-Order: regular headers fall back to lexicographic order.
func TestRegularHeaderOrder_DefaultLexicographic(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["X-C"] = []string{"1"}
	req.Header["X-A"] = []string{"2"}
	req.Header["X-B"] = []string{"3"}

	names := encode(t, req, "")
	assertSubsequence(t, names, []string{"x-a", "x-b", "x-c"})
}

// The magic order keys must never be emitted as real headers, and must not
// trip header-name validation.
func TestOrderKeysNotEmitted(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["X-A"] = []string{"1"}
	req.Header[httpcommon.HeaderOrderKey] = []string{"x-a"}
	req.Header[httpcommon.PHeaderOrderKey] = []string{":method", ":authority", ":path", ":scheme"}

	names := encode(t, req, "")
	for _, n := range names {
		if strings.EqualFold(n, httpcommon.HeaderOrderKey) || strings.EqualFold(n, httpcommon.PHeaderOrderKey) {
			t.Fatalf("magic order key %q leaked onto the wire: %v", n, names)
		}
	}
}

// v0.60 upstream addition: extended-CONNECT requests with an invalid :protocol
// token must be rejected.
func TestExtendedConnect_InvalidProtocolRejected(t *testing.T) {
	req, err := http.NewRequest(http.MethodConnect, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Proto = "bad protocol" // contains a space -> not a valid token

	w := newRequestWriter()
	if _, err := w.encodeHeaders(req, false, "", 0, true); err == nil {
		t.Fatal("expected error for invalid extended-CONNECT :protocol, got nil")
	}
}

// A valid extended-CONNECT :protocol token must be accepted and emitted.
func TestExtendedConnect_ValidProtocolAccepted(t *testing.T) {
	req, err := http.NewRequest(http.MethodConnect, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Proto = "websocket"

	names := encode(t, req, "")
	if indexOf(names, ":protocol") < 0 {
		t.Fatalf(":protocol pseudo-header not emitted: %v", names)
	}
}
