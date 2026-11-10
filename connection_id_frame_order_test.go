package quic

import (
	"github.com/enetx/quic-go/internal/ackhandler"
	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"math/rand/v2"
	"testing"
)

func TestConnectionIDFrameOrderingAcrossPackets(t *testing.T) {
	for _, sorted := range []bool{false, true} {
		f := newFramer(nil)
		f.sortConnectionIDFrames = sorted
		a := &wire.NewConnectionIDFrame{SequenceNumber: 2, ConnectionID: protocol.ParseConnectionID([]byte{2})}
		b := &wire.NewConnectionIDFrame{SequenceNumber: 3, ConnectionID: protocol.ParseConnectionID([]byte{3})}
		c := &wire.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: protocol.ParseConnectionID([]byte{1})}
		f.QueueControlFrame(a)
		f.QueueControlFrame(&wire.PingFrame{})
		f.QueueControlFrame(b)
		f.QueueControlFrame(c)
		// A one-frame packet tests that the remaining queue retains its order.
		frames, _ := f.AppendControlFrames(nil, c.Length(protocol.Version1), monotime.Now(), protocol.Version1)
		require.Len(t, frames, 1)
		all := []uint64{frames[0].Frame.(*wire.NewConnectionIDFrame).SequenceNumber}
		rest, _ := f.AppendControlFrames(nil, 1200, monotime.Now(), protocol.Version1)
		require.Len(t, rest, 3)
		require.IsType(t, &wire.PingFrame{}, rest[1].Frame)
		for _, fr := range rest {
			if id, ok := fr.Frame.(*wire.NewConnectionIDFrame); ok {
				all = append(all, id.SequenceNumber)
			}
		}
		if sorted {
			require.Equal(t, []uint64{1, 2, 3}, all)
		} else {
			require.Equal(t, []uint64{1, 3, 2}, all)
		}
	}
}

type connectionIDOrderHandler struct{ sequence uint64 }

func (*connectionIDOrderHandler) OnAcked(wire.Frame) {}
func (*connectionIDOrderHandler) OnLost(wire.Frame)  {}

func TestConnectionIDFrameOrderSurvivesSerializationShuffle(t *testing.T) {
	for seed := range uint64(100) {
		p := &packetPacker{sortConnectionIDFrames: true, rand: *rand.New(rand.NewPCG(seed, seed+1))}
		pl := payload{}
		for _, seq := range []uint64{3, 1, 2} {
			frame := &wire.NewConnectionIDFrame{SequenceNumber: seq, ConnectionID: protocol.ParseConnectionID([]byte{byte(seq)})}
			pl.frames = append(pl.frames, ackhandler.Frame{Frame: frame, Handler: &connectionIDOrderHandler{sequence: seq}})
			pl.length += frame.Length(protocol.Version1)
		}
		raw, err := p.appendPacketPayload(nil, pl, 0, protocol.Version1)
		require.NoError(t, err)
		require.EqualValues(t, pl.length, len(raw))
		for i, frame := range pl.frames {
			require.EqualValues(t, i+1, frame.Frame.(*wire.NewConnectionIDFrame).SequenceNumber)
			require.EqualValues(t, i+1, frame.Handler.(*connectionIDOrderHandler).sequence)
		}
	}
}
