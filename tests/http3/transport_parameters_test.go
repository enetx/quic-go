package http3_test

import (
	"context"
	"crypto/tls"
	"io"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
)

type parameterTrace struct{ received chan qlog.ParametersSet }

func (p *parameterTrace) AddProducer() qlogwriter.Recorder { return p }
func (p *parameterTrace) Close() error                     { return nil }
func (p *parameterTrace) RecordEvent(event qlogwriter.Event) {
	if e, ok := event.(qlog.ParametersSet); ok && e.Initiator == qlog.InitiatorRemote {
		select {
		case p.received <- e:
		default:
		}
	}
}

// Observe decoded parameters at the receiving endpoint, rather than asserting
// that the client retained a Config literal. All APIs here are official quic-go.
func TestOfficialQUICParametersReachPeer(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "extensions-off", true: "extensions-on"}[enabled], func(t *testing.T) {
			certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			certificates := certServer.TLS.Certificates
			certServer.Close()
			trace := &parameterTrace{received: make(chan qlog.ParametersSet, 1)}
			listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: certificates, NextProtos: []string{"h3"}}, &quic.Config{
				EnableDatagrams: true, EnableStreamResetPartialDelivery: true,
				Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			server := &http3.Server{EnableDatagrams: true, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })}
			go server.ServeListener(listener)
			defer server.Close()
			config := &quic.Config{
				Versions:                   []quic.Version{quic.Version1},
				InitialStreamReceiveWindow: 128 << 10, MaxStreamReceiveWindow: 128 << 10,
				InitialConnectionReceiveWindow: 2 << 20, MaxConnectionReceiveWindow: 2 << 20,
				MaxIncomingStreams: 7, MaxIncomingUniStreams: 11,
				MaxIdleTimeout: 24 * time.Second, InitialPacketSize: 1350,
				DisablePathMTUDiscovery: true, EnableDatagrams: enabled,
				EnableStreamResetPartialDelivery: enabled,
				RequireStreamCreditRelease:       true,
			}
			transport := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, QUICConfig: config, EnableDatagrams: enabled}
			defer transport.Close()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			resp, err := client.Get("https://" + listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-trace.received:
				if got.InitialMaxData != 2<<20 || got.InitialMaxStreamDataBidiLocal != 128<<10 || got.InitialMaxStreamDataBidiRemote != 128<<10 || got.InitialMaxStreamDataUni != 128<<10 {
					t.Fatalf("peer flow control parameters = %+v", got)
				}
				if got.InitialMaxStreamsBidi != 7 || got.InitialMaxStreamsUni != 11 || got.MaxIdleTimeout != 24*time.Second {
					t.Fatalf("peer limits = %+v", got)
				}
				if got.EnableResetStreamAt != enabled || (got.MaxDatagramFrameSize > 0) != enabled {
					t.Fatalf("peer extensions = %+v", got)
				}
			case <-time.After(time.Second):
				t.Fatal("peer did not record transport parameters")
			}
		})
	}
}
