package http3

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/enetx/quic-go"
	dynamic "github.com/enetx/quic-go/internal/qpack"
	"github.com/enetx/quic-go/quicvarint"
)

// QPACKStreamType identifies a client QPACK unidirectional stream.
type QPACKStreamType uint64

const (
	QPACKEncoderStream QPACKStreamType = 2
	QPACKDecoderStream QPACKStreamType = 3
)

// QPACKCapacityTiming selects when to queue an encoder capacity instruction.
type QPACKCapacityTiming uint8

const (
	QPACKCapacityOnSettings QPACKCapacityTiming = iota
	QPACKCapacityBeforeHeaders
)

// QPACKConfig controls client stream creation and capacity announcements.
// Nil preserves native behavior. It does not enable dynamic request encoding:
// outgoing field sections still have zero Required Insert Count.
type QPACKConfig struct {
	// StreamOrder reserves these streams after the control stream, in order,
	// while stream credit permits. Omitted streams are opened on demand.
	StreamOrder []QPACKStreamType
	// EagerStreamTypes queues the type byte at initialization for listed streams.
	// Otherwise the type is sent with the first instruction on that stream.
	EagerStreamTypes bool
	// EncoderTableCapacity bounds the capacity announced to the peer. Zero
	// disables announcements. The actual value is capped by peer SETTINGS.
	EncoderTableCapacity uint64
	// EncoderCapacityTiming selects immediate queuing after SETTINGS or queuing
	// while encoding the next HEADERS block. Network delivery remains asynchronous.
	EncoderCapacityTiming QPACKCapacityTiming
}

// Clone snapshots the mutable stream order.
func (q *QPACKConfig) Clone() *QPACKConfig {
	if q == nil {
		return nil
	}
	copy := *q
	copy.StreamOrder = slices.Clone(q.StreamOrder)
	return &copy
}

// Validate checks stream types, duplicate reservations and capacity bounds.
func (q *QPACKConfig) Validate() error {
	if q == nil {
		return nil
	}
	seen := make(map[QPACKStreamType]bool, 2)
	for _, typ := range q.StreamOrder {
		if (typ != QPACKEncoderStream && typ != QPACKDecoderStream) || seen[typ] {
			return fmt.Errorf("http3: invalid or duplicate QPACK stream type: %d", typ)
		}
		seen[typ] = true
	}
	if q.EncoderTableCapacity > quicvarint.Max {
		return errors.New("http3: QPACK encoder table capacity exceeds protocol range")
	}
	if q.EncoderCapacityTiming > QPACKCapacityBeforeHeaders {
		return errors.New("http3: invalid QPACK encoder capacity timing")
	}
	return nil
}

// Each critical stream has one writer. A blocked stream cannot block the control
// stream parser or request headers; the bounded queue retains instruction order.
type clientQPACKStream struct {
	owner  *rawConn
	typ    QPACKStreamType
	stream *quic.SendStream // reserved before ready is closed, then owned by run
	queue  chan []byte
	ready  <-chan struct{}
	eager  bool // set before ready is closed
}

func (s *clientQPACKStream) enqueue(data []byte) error {
	select {
	case <-s.owner.conn.Context().Done():
		return context.Cause(s.owner.conn.Context())
	default:
	}
	select {
	case s.queue <- data:
		return nil
	default:
		return errQPACKFeedbackBacklog
	}
}

func (s *clientQPACKStream) watch() {
	context.AfterFunc(s.stream.Context(), func() {
		_, stopped := errors.AsType[*quic.StreamError](context.Cause(s.stream.Context()))
		if stopped && s.owner.conn.Context().Err() == nil {
			s.owner.CloseWithError(quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), "QPACK send stream closed")
		}
	})
}

func (s *clientQPACKStream) run() {
	ctx := s.owner.conn.Context()
	select {
	case <-ctx.Done():
		return
	case <-s.ready:
	}
	typeSent := false
	pendingType := s.eager
	for {
		var data []byte
		if pendingType {
			pendingType = false
		} else {
			select {
			case <-ctx.Done():
				return
			case data = <-s.queue:
			}
		}
		if s.stream == nil {
			var err error
			s.stream, err = s.owner.conn.OpenUniStreamSync(ctx)
			if err != nil {
				return
			}
			s.watch()
		}
		if !typeSent {
			data = append(quicvarint.Append(nil, uint64(s.typ)), data...)
			typeSent = true
		}
		if _, err := s.stream.Write(data); err != nil {
			s.owner.CloseWithError(quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), "QPACK send stream write failed")
			return
		}
	}
}

type clientQPACK struct {
	config           *QPACKConfig
	encoder, decoder *clientQPACKStream
	mutex            sync.Mutex
	pendingCapacity  uint64
}

func newClientQPACK(owner *rawConn, config *QPACKConfig, ready <-chan struct{}, queueSize int) *clientQPACK {
	q := &clientQPACK{config: config.Clone()}
	q.encoder = &clientQPACKStream{owner: owner, typ: QPACKEncoderStream, ready: ready, queue: make(chan []byte, 2)}
	q.decoder = &clientQPACKStream{owner: owner, typ: QPACKDecoderStream, ready: ready, queue: make(chan []byte, queueSize)}
	go q.encoder.run()
	go q.decoder.run()
	return q
}

func (q *clientQPACK) prepare() error {
	if err := q.config.Validate(); err != nil {
		return err
	}
	for _, typ := range q.config.StreamOrder {
		s := q.encoder
		if typ == QPACKDecoderStream {
			s = q.decoder
		}
		stream, err := s.owner.conn.OpenUniStream()
		if _, ok := errors.AsType[*quic.StreamLimitReachedError](err); ok {
			break // Open on demand when more credit becomes available.
		}
		if err != nil {
			return err
		}
		s.stream = stream
		s.watch()
	}
	if q.config.EagerStreamTypes {
		for _, typ := range q.config.StreamOrder {
			s := q.encoder
			if typ == QPACKDecoderStream {
				s = q.decoder
			}
			s.eager = true
		}
	}
	return nil
}

func (q *clientQPACK) onSettings(capacity uint64) error {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	q.pendingCapacity = min(capacity, q.config.EncoderTableCapacity)
	if q.config.EncoderCapacityTiming == QPACKCapacityOnSettings {
		return q.flushCapacity()
	}
	return nil
}

func (q *clientQPACK) beforeHeaders() error {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	return q.flushCapacity()
}

func (q *clientQPACK) flushCapacity() error {
	if q.pendingCapacity == 0 {
		return nil // No instructions are permitted while the peer's limit is zero.
	}
	if err := q.encoder.enqueue(dynamic.AppendEncoderCapacity(nil, q.pendingCapacity)); err != nil {
		return err
	}
	q.pendingCapacity = 0
	return nil
}
