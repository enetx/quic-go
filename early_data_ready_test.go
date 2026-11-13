package quic

import (
	"errors"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/ackhandler"
	"github.com/enetx/quic-go/internal/handshake"
	"github.com/enetx/quic-go/internal/mocks"
	mockackhandler "github.com/enetx/quic-go/internal/mocks/ackhandler"
	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestEarlyDataReadinessRestoresCreditBeforeSetup(t *testing.T) {
	for _, phase := range []string{"native", "coalesced", "separate"} {
		t.Run(phase, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			crypto := mocks.NewMockCryptoSetup(ctrl)
			calls := 0
			h := &ClientHandshake{FlushEarlyData: phase == "separate"}
			if phase != "native" {
				h.OnEarlyDataReady = func(c *Conn) {
					calls++
					stream, err := c.OpenUniStream()
					require.NoError(t, err)
					require.NoError(t, stream.TryWriteAll([]byte("early control bytes")))
				}
			}
			tc := newClientTestConnection(t, ctrl, &Config{ClientHandshake: h}, true, connectionOptCryptoSetup(crypto))
			params := &wire.TransportParameters{ActiveConnectionIDLimit: 2, InitialMaxData: 4096, InitialMaxStreamDataUni: 1024, MaxUniStreamNum: 3}
			gomock.InOrder(
				crypto.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventRestoredTransportParameters, TransportParameters: params}),
				crypto.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
			)
			require.NoError(t, tc.conn.handleHandshakeEvents(monotime.Now()))
			require.Equal(t, phase == "separate", tc.conn.earlyDataReadyPending)
			wantCalls := 0
			if phase == "coalesced" {
				wantCalls = 1
			}
			require.Equal(t, wantCalls, calls)
			select {
			case <-tc.conn.earlyConnReadyChan:
				require.NotEqual(t, "separate", phase)
			default:
				require.Equal(t, "separate", phase)
			}
		})
	}
}

func TestEarlyDataReadinessRespectsInitialAndSendLimits(t *testing.T) {
	for _, scenario := range []string{"disabled", "initial-sendable", "queue-full", "congestion-limited", "empty-initial"} {
		t.Run(scenario, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			sender := NewMockSender(ctrl)
			packets := mockackhandler.NewMockSentPacketHandler(ctrl)
			ready := make(chan struct{})
			calls := 0
			c := &Conn{earlyConnReadyChan: ready, initialStream: newInitialCryptoStream(false), sendQueue: sender, sentPacketHandler: packets}
			c.config = &Config{ClientHandshake: &ClientHandshake{OnEarlyDataReady: func(*Conn) {
				calls++
				select {
				case <-ready:
					t.Error("application was released before setup")
				default:
				}
			}}}
			c.earlyDataReadyPending = scenario != "disabled"
			if scenario != "empty-initial" {
				_, err := c.initialStream.Write([]byte("pending ClientHello"))
				require.NoError(t, err)
			}
			switch scenario {
			case "initial-sendable":
				sender.EXPECT().WouldBlock().Return(false)
				packets.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny)
			case "queue-full":
				sender.EXPECT().WouldBlock().Return(true).Times(2)
			case "congestion-limited":
				sender.EXPECT().WouldBlock().Return(false).Times(2)
				packets.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendNone).Times(2)
			case "empty-initial":
				sender.EXPECT().WouldBlock().Return(false)
				packets.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendNone)
			}
			require.NoError(t, c.releaseEarlyData(monotime.Now()))
			want := scenario != "disabled" && scenario != "initial-sendable"
			require.Equal(t, map[bool]int{false: 0, true: 1}[want], calls)
			select {
			case <-ready:
				require.True(t, want)
			default:
				require.False(t, want)
			}
			if want {
				require.NoError(t, c.releaseEarlyData(monotime.Now()))
				require.Equal(t, 1, calls, "setup and channel publication must happen once")
			}
		})
	}
}

func TestEarlyDataReadinessDoesNotBypassPacingOrHidePackingErrors(t *testing.T) {
	for _, pacing := range []bool{false, true} {
		t.Run(map[bool]string{false: "packing-error", true: "pacing-limited"}[pacing], func(t *testing.T) {
			ctrl := gomock.NewController(t)
			sender := NewMockSender(ctrl)
			packets := mockackhandler.NewMockSentPacketHandler(ctrl)
			calls := 0
			tc := newClientTestConnection(t, ctrl, &Config{ClientHandshake: &ClientHandshake{OnEarlyDataReady: func(*Conn) { calls++ }}}, true,
				connectionOptSender(sender), connectionOptSentPacketHandler(packets))
			c := tc.conn.Conn
			c.earlyDataReadyPending = true
			sender.EXPECT().WouldBlock().Return(false)
			failure := errors.New("cannot serialize setup packet")
			deadline := monotime.Now().Add(time.Second)
			if pacing {
				packets.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited)
				packets.EXPECT().TimeUntilSend().Return(deadline)
				packets.EXPECT().ECNMode(false).Return(protocol.ECNNon)
				tc.packer.EXPECT().PackCoalescedPacket(true, gomock.Any(), gomock.Any(), protocol.Version1).Return(nil, nil)
			} else {
				packets.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny)
				tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1).Return(nil, failure)
			}
			err := c.releaseEarlyData(monotime.Now())
			require.Equal(t, 1, calls)
			if pacing {
				require.NoError(t, err)
				require.Equal(t, deadline, c.pacingDeadline)
				select {
				case <-c.earlyConnReadyChan:
				default:
					t.Fatal("pacing prevented application readiness")
				}
			} else {
				require.ErrorIs(t, err, failure)
				select {
				case <-c.earlyConnReadyChan:
					t.Fatal("failed setup released an early connection")
				default:
				}
			}
		})
	}
}
