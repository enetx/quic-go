package quic

import (
	"container/list"

	"github.com/enetx/quic-go/internal/ackhandler"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/enetx/quic-go/quicvarint"
)

// Protected by framer.mutex. Completion removes entries; an idle open stream
// keeps its place without retaining payload or a history of closed streams.
type streamCreationOrder struct {
	entries map[protocol.StreamID]*list.Element
	ids     list.List
}

func (f *framer) enableStreamCreationOrder() {
	f.creationOrder = &streamCreationOrder{entries: make(map[protocol.StreamID]*list.Element)}
}

func (f *framer) recordStreamCreation(id protocol.StreamID) {
	if f == nil || f.creationOrder == nil {
		return
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.recordStreamCreationLocked(id)
}

func (f *framer) recordStreamCreationLocked(id protocol.StreamID) {
	if f.creationOrder.entries[id] == nil {
		f.creationOrder.entries[id] = f.creationOrder.ids.PushBack(id)
	}
}

func (f *framer) appendStreamFramesByCreation(frames []ackhandler.Frame, streams []ackhandler.StreamFrame, maxLen, minimum protocol.ByteCount, v protocol.Version) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()
	f.mutex.Lock()
	defer f.mutex.Unlock()
	var length protocol.ByteCount
	var last *wire.StreamFrame
	appendStream := func(frame ackhandler.StreamFrame) {
		streams = append(streams, frame)
		n := frame.Frame.Length(v)
		length += n
		maxLen -= n
		last = frame.Frame
	}
	appendBlocked := func(frame wire.Frame) {
		n := frame.Length(v)
		if n > maxLen {
			f.controlFrames = append(f.controlFrames, frame)
			return
		}
		frames = append(frames, ackhandler.Frame{Frame: frame})
		length += n
		maxLen -= n
	}
	// A lost byte range remains ahead of new data, including when it is split
	// across packets. Within each class, retain creation order and skip blockers.
	for entry := f.creationOrder.ids.Front(); entry != nil && maxLen >= minimum; entry = entry.Next() {
		id := entry.Value.(protocol.StreamID)
		str := f.retransmissionStreams[id]
		if str == nil {
			continue
		}
		for maxLen >= minimum {
			frame, more := str.popRetransmissionFrame(maxLen+protocol.ByteCount(quicvarint.Len(uint64(maxLen))), v)
			if !more {
				delete(f.retransmissionStreams, id)
			}
			if frame.Frame != nil {
				appendStream(frame)
			}
			if !more || frame.Frame == nil {
				break
			}
		}
	}
	for entry := f.creationOrder.ids.Front(); entry != nil && maxLen >= minimum; entry = entry.Next() {
		id := entry.Value.(protocol.StreamID)
		str, ok := f.activeStreams[id]
		if !ok {
			continue
		}
		for maxLen >= minimum {
			frame, blocked, more := f.popStreamFrame(id, str, maxLen, v)
			if frame.Frame != nil {
				appendStream(frame)
			}
			if blocked != nil {
				appendBlocked(blocked)
			}
			if !more || frame.Frame == nil {
				break
			}
		}
	}
	if blocked, offset := f.connFlowController.IsNewlyBlocked(); blocked {
		appendBlocked(&wire.DataBlockedFrame{MaximumData: offset})
	}
	if last != nil {
		length -= last.Length(v)
		last.DataLenPresent = false
		length += last.Length(v)
	}
	return frames, streams, length
}
