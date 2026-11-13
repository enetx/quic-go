package ackhandler

import (
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

type probeStreamRecorder struct {
	acked, lost, probed int
	useful              bool
}

func (r *probeStreamRecorder) OnAcked(wire.Frame)       { r.acked++; r.useful = false }
func (r *probeStreamRecorder) OnLost(wire.Frame)        { r.lost++ }
func (r *probeStreamRecorder) OnProbe(wire.Frame) bool  { r.probed++; return r.useful }
func (r *probeStreamRecorder) HasOutstandingData() bool { return r.useful }

func streamRecoveryHandler(t *testing.T) *sentPacketHandler {
	t.Helper()
	h := NewSentPacketHandler(0, 1252, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger, ClientSendConfig{StreamDataRecovery: true, DisablePacketNumberSkipping: true, SeparatePacketNumberSpaces: true}).(*sentPacketHandler)
	h.DropPackets(protocol.EncryptionInitial, monotime.Now())
	h.DropPackets(protocol.EncryptionHandshake, monotime.Now())
	return h
}

func TestApplicationProbePreservesOriginalSTREAMACKAndFlightBytes(t *testing.T) {
	h := streamRecoveryHandler(t)
	now := monotime.Now()
	r := &probeStreamRecorder{useful: true}
	pn := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
	h.SentPacket(now, pn, protocol.InvalidPacketNumber, []StreamFrame{{Frame: &wire.StreamFrame{Data: []byte("original")}, Handler: r}}, nil, protocol.Encryption1RTT, protocol.ECNNon, 1252, false, false)
	require.True(t, h.QueueProbePacket(protocol.PacketNumberSpaceAppData))
	require.Equal(t, 1, r.probed)
	require.Zero(t, r.lost)
	require.EqualValues(t, 1252, h.bytesInFlight)
	require.False(t, h.QueueProbePacket(protocol.PacketNumberSpaceAppData))
	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.Encryption1RTT, now.Add(time.Millisecond))
	require.NoError(t, err)
	require.Equal(t, 1, r.acked)
	require.Zero(t, h.bytesInFlight)
	require.Zero(t, h.appDataPackets.numOutstanding)
}

func TestLostSTREAMPacketStillDeliversLateOriginalACK(t *testing.T) {
	h := streamRecoveryHandler(t)
	now := monotime.Now()
	r := &probeStreamRecorder{useful: true}
	for n := 0; n < 4; n++ {
		pn := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
		var stream []StreamFrame
		var frames []Frame
		if n == 0 {
			stream = []StreamFrame{{Frame: &wire.StreamFrame{Data: []byte("lost")}, Handler: r}}
		} else {
			frames = []Frame{{Frame: &wire.PingFrame{}}}
		}
		h.SentPacket(now, pn, protocol.InvalidPacketNumber, stream, frames, protocol.Encryption1RTT, protocol.ECNNon, 100, false, false)
	}
	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(3)}, protocol.Encryption1RTT, now.Add(time.Millisecond))
	require.NoError(t, err)
	require.Equal(t, 1, r.lost)
	require.Len(t, h.retainedStreamPackets, 1)
	flight := h.bytesInFlight
	h.ptoCount = 2
	h.numProbesToSend = 2
	acked1RTT, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(0)}, protocol.Encryption1RTT, now.Add(time.Millisecond+time.Microsecond))
	require.NoError(t, err)
	require.True(t, acked1RTT)
	require.Equal(t, 1, r.acked)
	require.Equal(t, flight, h.bytesInFlight, "already lost bytes must not be removed twice")
	require.Empty(t, h.retainedStreamPackets)
	require.Zero(t, h.ptoCount)
	require.Zero(t, h.numProbesToSend)
}

func TestLostSTREAMRetentionAndRejectionIsolation(t *testing.T) {
	for _, mode := range []string{"expiry", "rejection", "retry"} {
		t.Run(mode, func(t *testing.T) {
			h := streamRecoveryHandler(t)
			now := monotime.Now()
			r := &probeStreamRecorder{useful: true}
			p := &packet{EncryptionLevel: protocol.Encryption0RTT, StreamFrames: []StreamFrame{{Frame: &wire.StreamFrame{}, Handler: r}}}
			h.retainStreamPacket(0, p, now)
			require.Len(t, h.retainedStreamPackets, 1)
			switch mode {
			case "expiry":
				h.streamLossRetention = func(info StreamLossInfo) bool { return info.TimeSinceLoss < time.Second }
				h.expireRetainedStreams(now.Add(time.Second - time.Nanosecond))
				require.Len(t, h.retainedStreamPackets, 1)
				h.expireRetainedStreams(now.Add(time.Second))
			case "rejection":
				h.DropPackets(protocol.Encryption0RTT, now)
			case "retry":
				// Retry normally precedes dropping Initial; restore the state it requires.
				h.initialPackets = newPacketNumberSpace()
				h.ResetForRetry(now)
			}
			require.Empty(t, h.retainedStreamPackets)
			require.Zero(t, r.acked)
		})
	}
}

func TestLostSTREAMRetentionObservesNextPacketBoundary(t *testing.T) {
	h := streamRecoveryHandler(t)
	now := monotime.Now()
	r := &probeStreamRecorder{useful: true}
	h.retainStreamPacket(0, &packet{EncryptionLevel: protocol.Encryption1RTT, StreamFrames: []StreamFrame{{Handler: r}}}, now)
	var observed StreamLossInfo
	h.streamLossRetention = func(info StreamLossInfo) bool { observed = info; return true }
	pn := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
	h.SentPacket(now.Add(time.Millisecond), pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 100, false, false)
	require.EqualValues(t, pn, observed.FirstPacketAfterLoss)
	require.Equal(t, time.Millisecond, observed.TimeSinceLoss)
	require.Positive(t, observed.ProbeTimeout)
}

func TestLostSTREAMRetentionUsesMatchingNumberDomain(t *testing.T) {
	for _, separate := range []bool{false, true} {
		h := NewSentPacketHandler(0, 1252, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger, ClientSendConfig{StreamDataRecovery: true, DisablePacketNumberSkipping: true, SeparatePacketNumberSpaces: separate}).(*sentPacketHandler)
		now := monotime.Now()
		r := &probeStreamRecorder{useful: true}
		pn := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
		stream := []StreamFrame{{Frame: &wire.StreamFrame{Data: []byte("early")}, Handler: r}}
		h.SentPacket(now, pn, protocol.InvalidPacketNumber, stream, nil, protocol.Encryption0RTT, protocol.ECNNon, 100, false, false)
		h.retainStreamPacket(pn, &packet{EncryptionLevel: protocol.Encryption0RTT, StreamFrames: stream}, now)
		var observed StreamLossInfo
		h.streamLossRetention = func(info StreamLossInfo) bool { observed = info; return true }
		handshakePN := h.PopPacketNumber(protocol.PacketNumberSpaceHandshake)
		h.SentPacket(now, handshakePN, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionHandshake, protocol.ECNNon, 100, false, false)
		_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(handshakePN)}, protocol.EncryptionHandshake, now.Add(time.Millisecond))
		require.NoError(t, err)
		require.EqualValues(t, 1, observed.FirstPacketAfterLoss)
		if separate {
			require.EqualValues(t, -1, observed.LargestAcknowledged)
		} else {
			require.EqualValues(t, handshakePN, observed.LargestAcknowledged)
		}
	}
}

func TestLostSTREAMMetadataBound(t *testing.T) {
	h := streamRecoveryHandler(t)
	h.retainedStreamPackets = make([]retainedStreamPacket, protocol.MaxTrackedSentPackets)
	for i := range h.retainedStreamPackets {
		h.retainedStreamPackets[i].number = protocol.PacketNumber(i)
	}
	recorder := &probeStreamRecorder{useful: true}
	h.retainStreamPacket(protocol.MaxTrackedSentPackets, &packet{EncryptionLevel: protocol.Encryption1RTT, StreamFrames: []StreamFrame{{Handler: recorder}}}, monotime.Now())
	require.Len(t, h.retainedStreamPackets, protocol.MaxTrackedSentPackets)
	require.EqualValues(t, 1, h.retainedStreamPackets[0].number)
	require.EqualValues(t, protocol.MaxTrackedSentPackets, h.retainedStreamPackets[len(h.retainedStreamPackets)-1].number)
}
