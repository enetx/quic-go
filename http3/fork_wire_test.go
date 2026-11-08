package http3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	httpcommon "github.com/enetx/http/headerorder"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3/qlog"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/quic-go/testutils/events"
	"github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

// Decode actual QPACK bytes, independently of the optional qlog header list.
func forkWireHeaders(t *testing.T, w *requestWriter, req *http.Request, recorder *events.Recorder) []qpack.HeaderField {
	t.Helper()
	var buf bytes.Buffer
	if recorder == nil {
		require.NoError(t, w.WriteRequestHeader(&buf, req, false, 0, nil))
	} else {
		require.NoError(t, w.WriteRequestHeader(&buf, req, false, 0, recorder))
	}
	typ, err := quicvarint.Read(&buf)
	require.NoError(t, err)
	require.EqualValues(t, 1, typ)
	length, err := quicvarint.Read(&buf)
	require.NoError(t, err)
	require.EqualValues(t, buf.Len(), length)
	return decodeQpackHeaderFields(t, buf.Bytes())
}

func TestForkHeaderOrderOnWire(t *testing.T) {
	for _, logging := range []bool{false, true} {
		name := "without qlog"
		if logging {
			name = "with qlog"
		}
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name, method, protocol string
				pseudoOrder            []string
				regularOrder           []string
				wantPseudo             []string
				wantRegular            []string
			}{
				{name: "default", method: http.MethodGet,
					wantPseudo:  []string{":authority", ":method", ":path", ":scheme"},
					wantRegular: []string{"x-a", "x-multi", "x-multi", "x-z"}},
				{name: "custom and unlisted fields", method: http.MethodGet,
					pseudoOrder:  []string{":method", ":scheme", ":authority", ":path", ":protocol", ":unknown"},
					regularOrder: []string{"x-z", "x-missing", "x-a"},
					wantPseudo:   []string{":method", ":scheme", ":authority", ":path"},
					wantRegular:  []string{"x-z", "x-a", "x-multi", "x-multi"}},
				{name: "CONNECT", method: http.MethodConnect,
					pseudoOrder: []string{":method", ":scheme", ":authority", ":path", ":protocol"},
					wantPseudo:  []string{":method", ":authority"},
					wantRegular: []string{"x-a", "x-multi", "x-multi", "x-z"}},
				{name: "Extended CONNECT", method: http.MethodConnect, protocol: "websocket",
					pseudoOrder: []string{":method", ":protocol", ":authority", ":scheme", ":path"},
					wantPseudo:  []string{":method", ":protocol", ":authority", ":scheme", ":path"},
					wantRegular: []string{"x-a", "x-multi", "x-multi", "x-z"}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					req, err := http.NewRequest(tc.method, "https://example.com/path?q=1", nil)
					require.NoError(t, err)
					if tc.protocol != "" {
						req.Proto = tc.protocol
					}
					req.Header = http.Header{"X-Z": {"last"}, "X-A": {"first"}, "X-Multi": {"one", "two"}, "User-Agent": nil}
					if tc.pseudoOrder != nil {
						req.Header[httpcommon.PHeaderOrderKey] = tc.pseudoOrder
					}
					if tc.regularOrder != nil {
						req.Header[httpcommon.HeaderOrderKey] = tc.regularOrder
					}
					var recorder *events.Recorder
					if logging {
						recorder = &events.Recorder{}
					}
					fields := forkWireHeaders(t, newRequestWriter(), req, recorder)
					var names, multi []string
					for _, hf := range fields {
						names = append(names, hf.Name)
						if hf.Name == "x-multi" {
							multi = append(multi, hf.Value)
						}
					}
					require.Equal(t, append(tc.wantPseudo, tc.wantRegular...), names)
					require.Equal(t, []string{"one", "two"}, multi)
					if logging {
						logged := recorder.Events(qlog.FrameCreated{})
						require.Len(t, logged, 1)
						headers := logged[0].(qlog.FrameCreated).Frame.Frame.(qlog.HeadersFrame).HeaderFields
						for i, hf := range fields {
							require.Equal(t, qlog.HeaderField{Name: hf.Name, Value: hf.Value}, headers[i])
						}
					}
				})
			}
		})
	}
}

func TestForkHeaderOrderDoesNotLeakAcrossRequests(t *testing.T) {
	w := newRequestWriter()
	for i := 0; i < 20; i++ {
		req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		require.NoError(t, err)
		req.Header = http.Header{"X-A": {"1"}, "X-Z": {"2"}, "User-Agent": nil}
		want := []string{"x-a", "x-z"}
		if i%2 == 0 {
			req.Header[httpcommon.HeaderOrderKey] = []string{"x-z", "x-a"}
			want = []string{"x-z", "x-a"}
		}
		fields := forkWireHeaders(t, w, req, nil)
		require.Equal(t, want, []string{fields[4].Name, fields[5].Name})
	}
}

func TestForkTransportOrderMetadataValidation(t *testing.T) {
	for _, tc := range []struct {
		name, key, value string
		wantError        bool
	}{
		{name: "metadata"},
		{name: "invalid ordinary name", key: "bad:name", value: "value", wantError: true},
		{name: "invalid ordinary value", key: "X-Test", value: "bad\r\nvalue", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
			require.NoError(t, err)
			req.Header[httpcommon.HeaderOrderKey] = []string{"x-test"}
			req.Header[httpcommon.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}
			if tc.key != "" {
				req.Header[tc.key] = []string{tc.value}
			}
			var tr Transport
			defer tr.Close()
			_, err = tr.RoundTripOpt(req, RoundTripOpt{OnlyCachedConn: true})
			if tc.wantError {
				require.Error(t, err)
				require.False(t, errors.Is(err, ErrNoCachedConn))
			} else {
				require.ErrorIs(t, err, ErrNoCachedConn)
			}
			_, err = newRequestWriter().encodeHeaders(req, false, "", 0, false)
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func readForkControlSettings(t *testing.T, peer *quic.Conn) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	str, err := peer.AcceptUniStream(ctx)
	require.NoError(t, err)
	require.NoError(t, str.SetReadDeadline(time.Now().Add(time.Second)))
	r := quicvarint.NewReader(str)
	typ, err := quicvarint.Read(r)
	require.NoError(t, err)
	require.EqualValues(t, streamTypeControlStream, typ)
	typ, err = quicvarint.Read(r)
	require.NoError(t, err)
	require.EqualValues(t, 4, typ)
	n, err := quicvarint.Read(r)
	require.NoError(t, err)
	b := make([]byte, n)
	_, err = io.ReadFull(r, b)
	require.NoError(t, err)
	return b
}

func TestForkSettingsOnClientAndServerWire(t *testing.T) {
	// Profile settings include recognized settings, which must keep their supplied positions.
	settings := g.NewMapOrd[uint64, uint64]()
	settings.Insert(0x40, 17)
	settings.Insert(settingMaxFieldSectionSize, 12345)
	settings.Insert(1, 65536)
	settings.Insert(settingExtendedConnect, 1)
	settings.Insert(settingDatagram, 1)
	settings.Insert(0x21, 0)
	want := []uint64{0x40, 17, settingMaxFieldSectionSize, 12345, 1, 65536, settingExtendedConnect, 1, settingDatagram, 1, 0x21, 0}
	for _, server := range []bool{false, true} {
		name := "client"
		if server {
			name = "server"
		}
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := newConnPair(t)
			var wire []byte
			expected := want
			if server {
				serverSettings := g.NewMapOrd[uint64, uint64]()
				serverSettings.Insert(0x40, 17)
				serverSettings.Insert(1, 65536)
				serverSettings.Insert(0x21, 0)
				s := Server{AdditionalSettings: serverSettings}
				s.init()
				go s.handleConn(serverConn)
				wire = readForkControlSettings(t, clientConn)
				// Server defaults precede additional settings, as in the original fork.
				expected = append([]uint64{settingMaxFieldSectionSize, uint64(s.maxHeaderBytes()), settingExtendedConnect, 1}, []uint64{0x40, 17, 1, 65536, 0x21, 0}...)
			} else {
				tr := Transport{AdditionalSettings: settings, MaxResponseHeaderBytes: 999}
				tr.NewClientConn(clientConn)
				wire = readForkControlSettings(t, serverConn)
			}
			r := bytes.NewReader(wire)
			var got []uint64
			for r.Len() > 0 {
				v, err := quicvarint.Read(r)
				require.NoError(t, err)
				got = append(got, v)
			}
			require.Equal(t, expected, got)
		})
	}
}

func TestForkClientDoesNotAdvertiseLocalHeaderLimit(t *testing.T) {
	for _, limit := range []int{0, 1234} {
		clientConn, serverConn := newConnPair(t)
		tr := Transport{MaxResponseHeaderBytes: limit}
		cc := tr.NewClientConn(clientConn)
		require.Empty(t, readForkControlSettings(t, serverConn))
		expected := limit
		if expected == 0 {
			expected = defaultMaxResponseHeaderBytes
		}
		require.Equal(t, expected, cc.maxResponseHeaderBytes)
	}
}

func TestForkSettingsQlogSnapshot(t *testing.T) {
	other := g.NewMapOrd[uint64, uint64]()
	other.Insert(0x40, 10)
	other.Insert(0x21, 20)
	sf := &settingsFrame{MaxFieldSectionSize: -1, Other: other}
	var recorder events.Recorder
	fp := frameParser{r: bytes.NewReader(sf.Append(nil))}
	frame, err := fp.ParseNext(&recorder)
	require.NoError(t, err)
	parsed := frame.(*settingsFrame)
	require.Equal(t, other, parsed.Other)
	parsed.Other.Insert(0x40, 99)
	logged := recorder.Events(qlog.FrameParsed{})
	require.Len(t, logged, 1)
	require.Equal(t, map[uint64]uint64{0x40: 10, 0x21: 20}, logged[0].(qlog.FrameParsed).Frame.Frame.(qlog.SettingsFrame).Other)

	clientConn, serverConn := newConnPair(t, withClientRecorder(&recorder))
	tr := Transport{AdditionalSettings: other}
	tr.NewClientConn(clientConn)
	readForkControlSettings(t, serverConn)
	logged = recorder.Events(qlog.FrameCreated{})
	require.Len(t, logged, 1)
	other.Insert(0x40, 100)
	created := logged[0].(qlog.FrameCreated).Frame.Frame.(qlog.SettingsFrame)
	require.Equal(t, map[uint64]uint64{0x40: 10, 0x21: 20}, created.Other)
	require.EqualValues(t, -1, created.MaxFieldSectionSize)
}

func TestForkLocalResponseHeaderLimitStillEnforced(t *testing.T) {
	server := Server{TLSConfig: getTLSConfig(), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Large", strings.Repeat("x", 1024))
		w.WriteHeader(http.StatusOK)
	})}
	conn := newUDPConnLocalhost(t)
	go server.Serve(conn)
	t.Cleanup(func() { server.Close() })
	tr := Transport{TLSClientConfig: getTLSClientConfig(), MaxResponseHeaderBytes: 64}
	t.Cleanup(func() { tr.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+conn.LocalAddr().String(), nil)
	require.NoError(t, err)
	_, err = tr.RoundTrip(req)
	require.ErrorContains(t, err, "HEADERS frame too large")
}

func TestForkZeroHeaderLimitInSessionTickets(t *testing.T) {
	for _, previous := range []int64{-1, 0, 100} {
		ticket := settingsForSessionTicket(&settings{MaxFieldSectionSize: previous})
		data, ok := settingsDataFromSessionTicket([][]byte{ticket})
		require.True(t, ok)
		require.True(t, settingsCompatibleFor0RTT(data, &settings{MaxFieldSectionSize: 0}))
	}
}
