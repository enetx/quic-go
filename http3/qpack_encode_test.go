package http3

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/quicvarint"
	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func decodeStaticQPACK(t *testing.T, block []byte) []base.HeaderField {
	t.Helper()
	decode := base.NewDecoder().Decode(block)
	var fields []base.HeaderField
	for {
		field, err := decode()
		if err == io.EOF {
			return fields
		}
		require.NoError(t, err)
		fields = append(fields, field)
	}
}

func TestQPACKNeverIndexRepresentations(t *testing.T) {
	for _, field := range []base.HeaderField{{Name: ":method", Value: "GET"}, {Name: "accept", Value: "*/*"}, {Name: "authorization", Value: "token"}, {Name: "x-private", Value: "secret"}} {
		t.Run(field.Name, func(t *testing.T) {
			w := newRequestWriter()
			w.qpackConfig = &QPACKConfig{NeverIndex: []string{field.Name}}
			for range 2 {
				require.NoError(t, w.writeQPACKField(field.Name, field.Value))
				block := bytes.Clone(w.headerBuf.Bytes())
				require.Equal(t, []byte{0, 0}, block[:2])
				if block[2]&0xc0 == 0x40 {
					require.EqualValues(t, 0x70, block[2]&0xf0)
				} else {
					require.EqualValues(t, 0x30, block[2]&0xf0)
				}
				fields := decodeStaticQPACK(t, block)
				require.Equal(t, []base.HeaderField{field}, fields)
				require.NoError(t, w.encoder.Close())
				w.headerBuf.Reset()
			}
		})
	}
}

func TestQPACKCookieSplitOrderAndTraceParity(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://localhost/", nil)
	req.Header["Cookie"] = []string{" first=1; second=2; ; third=3 ", "fourth=4"}
	req.Header["X-Before"] = []string{"before"}
	req.Header["X-After"] = []string{"after"}
	req.Header["Header-Order:"] = []string{"x-before", "cookie", "x-after"}
	original := req.Header.Clone()
	var previous []byte
	for _, trace := range []bool{false, true} {
		w := newRequestWriter()
		w.qpackConfig = &QPACKConfig{SplitCookies: true, NeverIndex: []string{"cookie"}}
		logged, err := w.encodeHeaders(req, false, "", 0, trace)
		require.NoError(t, err)
		block := bytes.Clone(w.headerBuf.Bytes())
		fields := decodeStaticQPACK(t, block)
		var cookies []string
		before, after := -1, -1
		for i, f := range fields {
			if f.Name == "cookie" {
				cookies = append(cookies, f.Value)
			}
			if f.Name == "x-before" {
				before = i
			}
			if f.Name == "x-after" {
				after = i
			}
		}
		require.Equal(t, []string{"first=1", "second=2", "third=3", "fourth=4"}, cookies)
		require.Equal(t, before+5, after)
		if trace {
			require.Equal(t, len(fields), len(logged))
			require.Equal(t, previous, block)
		}
		previous = block
	}
	require.True(t, reflect.DeepEqual(original, req.Header))
}

func TestHTTP3RequestFactoryErrorsDoNotWriteFrames(t *testing.T) {
	for _, factory := range []func(*http.Request) ([]GreaseFrame, error){
		func(*http.Request) ([]GreaseFrame, error) { return nil, errors.New("bad factory") },
		func(*http.Request) ([]GreaseFrame, error) { return []GreaseFrame{{Type: 1}}, nil },
	} {
		w := newRequestWriter()
		w.greaseFrames = factory
		req, _ := http.NewRequest("GET", "https://localhost/", nil)
		var out bytes.Buffer
		require.Error(t, w.WriteRequestHeader(&out, req, false, 0, nil))
		require.Zero(t, out.Len())
		w.greaseFrames = func(*http.Request) ([]GreaseFrame, error) { return []GreaseFrame{{Type: 33}}, nil }
		require.NoError(t, w.WriteRequestHeader(&out, req, false, 4, nil))
		kind, _, err := quicvarint.Parse(out.Bytes())
		require.NoError(t, err)
		require.EqualValues(t, 33, kind)
	}
}

func TestQPACKTrailersUseConnectionEncoderAndOrder(t *testing.T) {
	w := newRequestWriter()
	var sections [][]base.HeaderField
	w.encodeQPACK = func(id quic.StreamID, fields []base.HeaderField) ([]byte, error) {
		sections = append(sections, append([]base.HeaderField(nil), fields...))
		var encoded bytes.Buffer
		encoder := base.NewEncoder(&encoded)
		for _, field := range fields {
			if err := encoder.WriteField(field); err != nil {
				return nil, err
			}
		}
		return encoded.Bytes(), nil
	}
	req, err := http.NewRequest("POST", "https://localhost/", nil)
	require.NoError(t, err)
	req.Trailer = http.Header{"X-A": []string{"first", "second"}, "X-Z": []string{"last"}, "Header-Order:": []string{"x-z", "x-a"}}
	original := req.Trailer.Clone()
	var wire bytes.Buffer
	require.NoError(t, w.WriteRequestHeader(&wire, req, false, 0, nil))
	require.NoError(t, w.WriteRequestTrailer(&wire, req, 0, nil))
	require.Len(t, sections, 2)
	require.Contains(t, sections[0], base.HeaderField{Name: "trailer", Value: "X-Z, X-A"})
	require.Equal(t, []base.HeaderField{{Name: "x-z", Value: "last"}, {Name: "x-a", Value: "first"}, {Name: "x-a", Value: "second"}}, sections[1])
	require.Equal(t, original, req.Trailer)
	req.Trailer["X-Z"] = []string{"invalid\nvalue"}
	require.ErrorContains(t, w.WriteRequestTrailer(&wire, req, 0, nil), "trailer value")
	require.Len(t, sections, 2, "invalid trailers must not reach the stateful encoder")
	req.Trailer = http.Header{"bad name": []string{"value"}}
	require.ErrorContains(t, w.WriteRequestHeader(&wire, req, false, 4, nil), "trailer name")
	require.Len(t, sections, 2)
}
