package http3_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	h3log "github.com/enetx/quic-go/http3/qlog"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/quic-go/testutils/events"
	"github.com/stretchr/testify/require"
)

func TestInitialSettingsPrecedeRequestHeaders(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http3.Server{TLSConfig: testdata.GetTLSConfig(), Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })}
	go server.Serve(packet)
	t.Cleanup(func() { server.Close(); packet.Close() })
	settings := g.NewMapOrd[uint64, uint64]()
	settings.Insert(1, 65536)
	settings.Insert(7, 20)
	for range 20 {
		var recorder events.Recorder
		transport := &http3.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, AdditionalSettings: settings,
			QUICConfig: &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
				return &events.Trace{Recorder: &recorder}
			}},
		}
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		response, err := client.Get("https://" + packet.LocalAddr().String())
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, response.Body)
		require.NoError(t, err)
		response.Body.Close()
		transport.Close()
		frames := recorder.Events(h3log.FrameCreated{})
		require.NotEmpty(t, frames)
		require.IsType(t, h3log.SettingsFrame{}, frames[0].(h3log.FrameCreated).Frame.Frame)
		hasHeaders := false
		for _, frame := range frames {
			if _, ok := frame.(h3log.FrameCreated).Frame.Frame.(h3log.HeadersFrame); ok {
				hasHeaders = true
			}
		}
		require.True(t, hasHeaders, "no request headers were recorded")
		firstStream := int64(-1)
		for _, event := range recorder.Events(qlog.PacketSent{}) {
			for _, frame := range event.(qlog.PacketSent).Frames {
				if stream, ok := frame.Frame.(*qlog.StreamFrame); ok && firstStream == -1 {
					firstStream = int64(stream.StreamID)
				}
			}
		}
		require.EqualValues(t, 2, firstStream, "first transmitted stream must carry initial SETTINGS")
	}
}
