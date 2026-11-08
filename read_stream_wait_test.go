package quic

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestWaitForReadReady(t *testing.T) {
	for _, kind := range []string{"ready", "deadline-update", "clear-deadline", "context", "cancel", "reset", "connection", "fin"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				sender := NewMockStreamSender(gomock.NewController(t))
				sender.EXPECT().onHasStreamControlFrame(gomock.Any(), gomock.Any()).AnyTimes()
				sender.EXPECT().onStreamCompleted(gomock.Any()).AnyTimes()
				stream := newReceiveStream(0, sender, newTestStreamFlowController(0))
				ready := make(chan struct{})
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if kind == "clear-deadline" {
					stream.SetReadDeadline(time.Now().Add(time.Hour))
				}
				done := make(chan error, 1)
				go func() { done <- stream.WaitForReadReady(ctx, ready) }()
				synctest.Wait()
				switch kind {
				case "ready":
					close(ready)
				case "deadline-update":
					stream.SetReadDeadline(time.Now().Add(time.Second))
					time.Sleep(time.Second)
				case "clear-deadline":
					stream.SetReadDeadline(time.Time{})
					time.Sleep(2 * time.Hour)
					select {
					case err := <-done:
						t.Fatalf("cleared deadline fired: %v", err)
					default:
					}
					close(ready)
				case "context":
					cancel()
				case "cancel":
					stream.CancelRead(42)
				case "reset":
					require.NoError(t, stream.handleResetStreamFrame(&wire.ResetStreamFrame{ErrorCode: 42}, monotime.Now()))
				case "connection":
					stream.closeForShutdown(io.ErrUnexpectedEOF)
				case "fin":
					require.NoError(t, stream.handleStreamFrame(&wire.StreamFrame{Fin: true}, monotime.Now()))
					synctest.Wait()
					select {
					case err := <-done:
						t.Fatalf("FIN ended protocol wait: %v", err)
					default:
					}
					close(ready)
				}
				err := <-done
				switch kind {
				case "ready", "clear-deadline", "fin":
					require.NoError(t, err)
				case "deadline-update":
					require.ErrorIs(t, err, os.ErrDeadlineExceeded)
				case "context":
					require.ErrorIs(t, err, context.Canceled)
				case "connection":
					require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				default:
					var se *StreamError
					require.True(t, errors.As(err, &se))
					require.EqualValues(t, 42, se.ErrorCode)
				}
			})
		})
	}
}
