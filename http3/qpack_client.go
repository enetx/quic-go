package http3

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/enetx/quic-go"
	dynamic "github.com/enetx/quic-go/internal/qpack"
	"github.com/enetx/quic-go/quicvarint"
	base "github.com/quic-go/qpack"
	"golang.org/x/net/http/httpguts"
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

type (
	QPACKHuffmanMode  = dynamic.HuffmanMode
	QPACKIndexingMode = dynamic.IndexingMode
)

const (
	QPACKHuffmanDefault = dynamic.HuffmanDefault
	QPACKHuffmanAuto    = dynamic.HuffmanAuto
	QPACKHuffmanAlways  = dynamic.HuffmanAlways
	QPACKHuffmanNever   = dynamic.HuffmanNever
	QPACKIndexAll       = dynamic.IndexAll
	QPACKIndexNewNames  = dynamic.IndexNewNames
	QPACKIndexNone      = dynamic.IndexNone
)

// QPACKConfig controls client streams, capacity announcements and request fields.
// Nil preserves native behavior. Dynamic request compression is explicitly opt-in.
type QPACKConfig struct {
	DynamicTable bool
	Huffman      QPACKHuffmanMode
	Indexing     QPACKIndexingMode
	// IndexingPolicy controls insertion of new entries; existing references remain
	// usable. Called under encoder locks; must not reenter the transport.
	IndexingPolicy func(name, value string) bool
	// DrainingFraction reserves this fraction of table space for eviction.
	// Draining exact entries can be duplicated while their old references drain.
	DrainingFraction float64
	// PostBaseReferences fixes Base before this section's insertions. Otherwise
	// Base equals Required Insert Count and all references are Base-relative.
	PostBaseReferences bool
	// LiteralInsertNames disables name references in Insert instructions.
	LiteralInsertNames bool
	// StopOnInsertionFailure stops new insertion attempts for the rest of a
	// section after the first entry cannot fit. Existing references remain usable.
	StopOnInsertionFailure bool
	// MaxTrackedSections bounds outstanding dynamic section bookkeeping. Zero
	// selects 4096; at the limit new sections use static encoding without waiting.
	MaxTrackedSections uint64
	// SplitCookies emits one field per nonempty cookie-pair, preserving order.
	SplitCookies bool
	// NeverIndex emits these lowercase field names as literals with N=1.
	// These fields bypass the dynamic table entirely.
	NeverIndex []string
	// StreamOrder reserves these streams after the control stream, in order,
	// while stream credit permits. Omitted streams are opened on demand.
	StreamOrder []QPACKStreamType
	// EagerStreamTypes queues the type byte at initialization for listed streams.
	// Otherwise the type is sent with the first instruction on that stream.
	EagerStreamTypes bool
	// EncoderTableCapacity bounds the capacity announced to the peer. Zero
	// disables dynamic insertion. The actual value is capped by peer SETTINGS;
	// EncoderZeroCapacity separately controls explicit zero announcements.
	EncoderTableCapacity uint64
	// EncoderZeroCapacity sends a capacity-zero instruction even when the peer
	// offers no table, initializing an otherwise lazy encoder stream.
	EncoderZeroCapacity bool
	// EncoderCapacityRequiresSetting suppresses capacity announcements when
	// the peer omitted SETTINGS_QPACK_MAX_TABLE_CAPACITY. An explicit zero
	// remains distinct and is governed by EncoderZeroCapacity.
	EncoderCapacityRequiresSetting bool
	// EncoderCapacityTiming selects immediate queuing after SETTINGS or queuing
	// while encoding the next HEADERS block. Network delivery remains asynchronous.
	EncoderCapacityTiming QPACKCapacityTiming
}

// Clone snapshots the mutable stream order and field names.
func (q *QPACKConfig) Clone() *QPACKConfig {
	if q == nil {
		return nil
	}
	copy := *q
	copy.StreamOrder = slices.Clone(q.StreamOrder)
	copy.NeverIndex = slices.Clone(q.NeverIndex)
	return &copy
}

// Validate checks stream types, duplicate reservations and capacity bounds.
func (q *QPACKConfig) Validate() error {
	if q == nil {
		return nil
	}
	if err := q.encoderOptions().Validate(); err != nil {
		return fmt.Errorf("http3: invalid QPACK encoder options: %w", err)
	}
	for _, name := range q.NeverIndex {
		if name != strings.ToLower(name) || !httpguts.ValidHeaderFieldName(strings.TrimPrefix(name, ":")) {
			return fmt.Errorf("http3: invalid QPACK never-index name %q", name)
		}
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
	owner    *rawConn
	typ      QPACKStreamType
	stream   *quic.SendStream // reserved before ready is closed, then owned by run
	queue    chan []byte
	ready    <-chan struct{}
	eager    bool        // set before ready is closed
	reserved atomic.Bool // stream credit exists before admitting dynamic references
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
			s.reserved.Store(true)
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
	capacityPending  bool
	fieldEncoder     *dynamic.Encoder
}

func (q *QPACKConfig) encoderOptions() dynamic.EncoderOptions {
	return dynamic.EncoderOptions{DynamicTable: q.DynamicTable, Huffman: q.Huffman, Indexing: q.Indexing,
		IndexingPolicy: q.IndexingPolicy, DrainingFraction: q.DrainingFraction, PostBaseReferences: q.PostBaseReferences,
		LiteralInsertNames: q.LiteralInsertNames, MaxTrackedSections: q.MaxTrackedSections,
		StopOnInsertionFailure: q.StopOnInsertionFailure}
}

func newClientQPACK(owner *rawConn, config *QPACKConfig, ready <-chan struct{}, queueSize int) *clientQPACK {
	q := &clientQPACK{config: config.Clone(), fieldEncoder: dynamic.NewEncoder(config.encoderOptions())}
	q.encoder = &clientQPACKStream{owner: owner, typ: QPACKEncoderStream, ready: ready, queue: make(chan []byte, 64)}
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
		s.reserved.Store(true)
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

func (q *clientQPACK) onSettings(capacity, blockedStreams uint64, capacityAdvertised bool) error {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	q.pendingCapacity = min(capacity, q.config.EncoderTableCapacity)
	q.capacityPending = q.pendingCapacity > 0 || q.config.EncoderZeroCapacity && (!q.config.EncoderCapacityRequiresSetting || capacityAdvertised)
	if err := q.fieldEncoder.Configure(capacity, q.pendingCapacity, blockedStreams); err != nil {
		return err
	}
	if q.config.EncoderCapacityTiming == QPACKCapacityOnSettings {
		return q.flushCapacity()
	}
	return nil
}

func (q *clientQPACK) encode(streamID quic.StreamID, fields []base.HeaderField) ([]byte, error) {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	if err := q.flushCapacity(); err != nil {
		return nil, err
	}
	input := make([]dynamic.Field, len(fields))
	for i, field := range fields {
		input[i] = dynamic.Field{Name: field.Name, Value: field.Value, NeverIndex: slices.Contains(q.config.NeverIndex, field.Name)}
	}
	return q.fieldEncoder.Encode(uint64(streamID), input, func(data []byte) error {
		if !q.encoder.reserved.Load() {
			return dynamic.ErrEncoderBlocked
		}
		if err := q.encoder.enqueue(data); errors.Is(err, errQPACKFeedbackBacklog) {
			return dynamic.ErrEncoderBlocked
		} else {
			return err
		}
	})
}

func (q *clientQPACK) flushCapacity() error {
	if !q.capacityPending {
		return nil
	}
	if err := q.encoder.enqueue(dynamic.AppendEncoderCapacity(nil, q.pendingCapacity)); err != nil {
		return err
	}
	q.capacityPending = false
	return nil
}
