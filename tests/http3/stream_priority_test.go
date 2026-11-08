package http3_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
)

// The official qlog event records changes applied by the real QUIC scheduler.
// Keeping this in memory avoids depending on qlog's JSON schema and timing.
type priorityTrace struct {
	mu         sync.Mutex
	priorities []qlog.StreamPriorityUpdated
}

func (p *priorityTrace) AddProducer() qlogwriter.Recorder { return p }
func (p *priorityTrace) Close() error                     { return nil }
func (p *priorityTrace) RecordEvent(event qlogwriter.Event) {
	if e, ok := event.(qlog.StreamPriorityUpdated); ok {
		p.mu.Lock()
		p.priorities = append(p.priorities, e)
		p.mu.Unlock()
	}
}

func priorityServer(t *testing.T, datagrams bool) string {
	t.Helper()
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificates := certServer.TLS.Certificates
	certServer.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &http3.Server{
		EnableDatagrams: datagrams,
		TLSConfig:       &tls.Config{Certificates: certificates},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Priority") != "" {
				t.Error("local stream priority unexpectedly changed the HTTP Priority header")
			}
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				return
			}
			fmt.Fprint(w, "ok")
		}),
	}
	go s.Serve(udp)
	t.Cleanup(func() { s.Close(); udp.Close() })
	return "https://" + udp.LocalAddr().String()
}

func TestStreamPriority(t *testing.T) {
	url := priorityServer(t, false)
	for _, route := range []string{"transport", "connection", "raw"} {
		for _, tc := range []struct {
			name     string
			priority *http3.StreamPriority
			override *http3.StreamPriority
			want     *http3.StreamPriority
		}{
			{name: "default"},
			{name: "explicit-zero", priority: &http3.StreamPriority{Urgency: 0}, want: &http3.StreamPriority{Urgency: 0}},
			{name: "incremental", priority: &http3.StreamPriority{Urgency: 2, Incremental: true}, want: &http3.StreamPriority{Urgency: 2, Incremental: true}},
			{name: "clipped", priority: &http3.StreamPriority{Urgency: 99}, want: &http3.StreamPriority{Urgency: 7}},
			{name: "context", priority: &http3.StreamPriority{Urgency: 2}, override: &http3.StreamPriority{Urgency: 1, Incremental: true}, want: &http3.StreamPriority{Urgency: 1, Incremental: true}},
		} {
			t.Run(route+"/"+tc.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if tc.override != nil {
					ctx = http3.WithStreamPriority(ctx, *tc.override)
				}
				trace := new(priorityTrace)
				config := &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }}
				tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, QUICConfig: config, StreamPriority: tc.priority}
				defer tr.Close()
				var rt http.RoundTripper = tr
				if route != "transport" {
					conn, err := quic.DialAddr(ctx, url[len("https://"):], &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, config)
					if err != nil {
						t.Fatal(err)
					}
					defer conn.CloseWithError(0, "")
					if route == "connection" {
						rt = tr.NewClientConn(conn)
					} else {
						cc := tr.NewRawClientConn(conn)
						go func() {
							for {
								stream, err := conn.AcceptUniStream(ctx)
								if err != nil {
									return
								}
								go cc.HandleUnidirectionalStream(stream)
							}
						}()
						rt = cc
					}
				}
				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := rt.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || string(body) != "ok" {
					t.Fatalf("response = %q, %v", body, err)
				}
				trace.mu.Lock()
				defer trace.mu.Unlock()
				if tc.want == nil {
					if len(trace.priorities) != 0 {
						t.Fatalf("default priority overridden: %+v", trace.priorities)
					}
					return
				}
				if len(trace.priorities) != 1 {
					t.Fatalf("priority events = %+v", trace.priorities)
				}
				got := trace.priorities[0]
				if got.StreamID != 0 || got.Urgency != tc.want.Urgency || got.Incremental != tc.want.Incremental {
					t.Fatalf("priority = %+v, want stream 0 %+v", got, tc.want)
				}
			})
		}
	}
}

func TestStreamPrioritySnapshotAndManualStream(t *testing.T) {
	url := priorityServer(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	trace := new(priorityTrace)
	config := &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }}
	conn, err := quic.DialAddr(ctx, url[len("https://"):], &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	priority := &http3.StreamPriority{Urgency: 1}
	tr := &http3.Transport{StreamPriority: priority}
	cc := tr.NewClientConn(conn)
	priority.Urgency = 7 // Already constructed connections keep their snapshot.
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	stream, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream.SetPriority(6, true)
	if err := stream.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.ReadResponse(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, stream); err != nil {
		t.Fatal(err)
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	want := []qlog.StreamPriorityUpdated{
		{StreamID: 0, Urgency: 1}, {StreamID: 4, Urgency: 1},
		{StreamID: 4, Urgency: 6, Incremental: true},
	}
	if len(trace.priorities) != len(want) {
		t.Fatalf("events = %+v", trace.priorities)
	}
	for i := range want {
		if trace.priorities[i] != want[i] {
			t.Fatalf("event %d = %+v, want %+v", i, trace.priorities[i], want[i])
		}
	}
}

func TestOrderedDatagramSettingWithRuntimeEnabled(t *testing.T) {
	url := priorityServer(t, true)
	settings := g.NewMapOrd[uint64, uint64]()
	settings.Insert(1, 0)
	settings.Insert(0x33, 1)
	settings.Insert(7, 0)
	tr := &http3.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		QUICConfig:         &quic.Config{EnableDatagrams: true},
		EnableDatagrams:    true,
		AdditionalSettings: settings,
	}
	defer tr.Close()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestInvalidOrderedSettingsFailBeforeDial(t *testing.T) {
	for _, tc := range []struct{ id, value uint64 }{{0x33, 0}, {0x33, 2}, {0x8, 2}, {2, 0}, {3, 0}, {4, 0}, {5, 0}, {1 << 62, 0}, {42, 1 << 62}} {
		t.Run(fmt.Sprintf("%x=%d", tc.id, tc.value), func(t *testing.T) {
			settings := g.NewMapOrd[uint64, uint64]()
			settings.Insert(tc.id, tc.value)
			dialed := false
			tr := &http3.Transport{EnableDatagrams: true, QUICConfig: &quic.Config{EnableDatagrams: true}, AdditionalSettings: settings,
				Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
					dialed = true
					return nil, fmt.Errorf("unexpected dial")
				},
			}
			defer tr.Close()
			req, err := http.NewRequest("GET", "https://example.test", nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tr.RoundTrip(req); err == nil || dialed {
				t.Fatalf("error = %v, dialed = %v", err, dialed)
			}
		})
	}
}
