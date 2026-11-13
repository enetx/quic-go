package http3

import (
	"bytes"
	"crypto/tls"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/quic-go/tlsquic"
	"github.com/stretchr/testify/require"
)

type settingsEventTLS struct {
	tlsquic.Conn
	events []tls.QUICEvent
}

func (c *settingsEventTLS) NextEvent() tls.QUICEvent {
	event := c.events[0]
	c.events = c.events[1:]
	return event
}

func TestClientSessionSettingsHonorQUICResumeDecision(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		t.Run(map[bool]string{false: "transport-rejected", true: "allowed"}[allowed], func(t *testing.T) {
			state := &tls.SessionState{EarlyData: true, Extra: [][]byte{encodeClientSettings(&settingsFrame{MaxFieldSectionSize: 100})}}
			session := &clientSettingsSession{}
			provider := &clientSessionTLS{session: session, Conn: &settingsEventTLS{events: []tls.QUICEvent{
				{Kind: tls.QUICResumeSession, SessionState: state}, {Kind: tls.QUICNoEvent}, {Kind: tls.QUICRejectedEarlyData},
			}}}
			event := provider.NextEvent()
			require.Same(t, state, event.SessionState)
			// QUIC validates remembered transport parameters between TLS events.
			// The wrapper must observe that decision instead of the cache value.
			state.EarlyData = allowed
			provider.NextEvent()
			require.Equal(t, allowed, session.early)
			require.Nil(t, session.resume)
			provider.NextEvent()
			require.True(t, session.rejected)
		})
	}
	state := &tls.SessionState{EarlyData: true}
	provider := &clientSessionTLS{session: &clientSettingsSession{}, Conn: &settingsEventTLS{events: []tls.QUICEvent{{Kind: tls.QUICResumeSession, SessionState: state}}}}
	provider.NextEvent()
	require.False(t, state.EarlyData, "application state is required even for a provider bypassing Get")
}

func settingsTicket(t *testing.T, sf *settingsFrame, early bool) *tls.ClientSessionState {
	t.Helper()
	server := httptest.NewTLSServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) { io.WriteString(w, "ok") }))
	defer server.Close()
	cache := &settingsRecordingCache{}
	transport := &stdhttp.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ClientSessionCache: cache}}
	defer transport.CloseIdleConnections()
	response, err := (&stdhttp.Client{Transport: transport}).Get(server.URL)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	seed, ok := cache.Get("key")
	require.True(t, ok)
	_, state, err := seed.ResumptionState()
	require.NoError(t, err)
	state.EarlyData, state.Extra = early, [][]byte{[]byte("application-owned")}
	if sf != nil {
		state.Extra = append(state.Extra, encodeClientSettings(sf))
	}
	ticket, err := tls.NewResumptionState([]byte("opaque-ticket"), state)
	require.NoError(t, err)
	return ticket
}

func TestClientSessionSettingsMetadata(t *testing.T) {
	for _, limit := range []int64{-1, 0, 1, (1 << 62) - 1} {
		sf := &settingsFrame{MaxFieldSectionSize: limit, Datagram: true, ExtendedConnect: true,
			Other: orderedTestSettings(map[uint64]uint64{1: 4096, 7: 16, 0xdead: 19})}
		ticket := settingsTicket(t, sf, true)
		got, ok := ClientSessionSettings(ticket)
		require.True(t, ok)
		require.Equal(t, limit, got.MaxFieldSectionSize)
		require.True(t, got.EnableDatagrams)
		require.True(t, got.EnableExtendedConnect)
		require.EqualValues(t, 4096, got.Other.Get(1).Unwrap())
		got.Other.Insert(1, 0)
		again, ok := ClientSessionSettings(ticket)
		require.True(t, ok)
		require.EqualValues(t, 4096, again.Other.Get(1).Unwrap())
	}
	requireSettingsMissing := func(extras [][]byte) {
		t.Helper()
		ticket, err := tls.NewResumptionState([]byte("opaque"), &tls.SessionState{Extra: extras})
		require.NoError(t, err)
		_, ok := ClientSessionSettings(ticket)
		require.False(t, ok)
	}
	requireSettingsMissing(nil)
	requireSettingsMissing([][]byte{[]byte(clientSettingsPrefix)})
	requireSettingsMissing([][]byte{append([]byte(clientSettingsPrefix), 4, 1)})
	valid := encodeClientSettings(&settingsFrame{MaxFieldSectionSize: -1})
	requireSettingsMissing([][]byte{valid, valid})
	requireSettingsMissing([][]byte{append([]byte(clientSettingsPrefix), make([]byte, 65537)...)})
	_, ok := ClientSessionSettings(nil)
	require.False(t, ok)
}

type settingsRecordingCache struct {
	mutex  sync.Mutex
	ticket *tls.ClientSessionState
	puts   []*tls.ClientSessionState
}

func (c *settingsRecordingCache) Get(string) (*tls.ClientSessionState, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.ticket, c.ticket != nil
}
func (c *settingsRecordingCache) Put(_ string, state *tls.ClientSessionState) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.ticket = state
	c.puts = append(c.puts, state)
}

func TestClientSessionSettingsWaitForTheirOwnConnection(t *testing.T) {
	base := &settingsRecordingCache{}
	first := &clientSettingsSession{cache: base}
	second := &clientSettingsSession{cache: base}
	ticket := settingsTicket(t, nil, true)
	first.Put("key", ticket)
	first.Put("key", ticket)
	second.commitSettings(&settingsFrame{MaxFieldSectionSize: 200})
	require.Empty(t, base.puts, "another connection cannot supply this ticket's SETTINGS")
	first.commitSettings(&settingsFrame{MaxFieldSectionSize: 100, Other: orderedTestSettings(map[uint64]uint64{1: 4096})})
	require.Len(t, base.puts, 2)
	for _, stored := range base.puts {
		sf, ok := ClientSessionSettings(stored)
		require.True(t, ok)
		require.EqualValues(t, 100, sf.MaxFieldSectionSize)
		_, state, err := stored.ResumptionState()
		require.NoError(t, err)
		require.True(t, state.EarlyData)
		require.Equal(t, []byte("application-owned"), state.Extra[0])
	}
	_, original, err := ticket.ResumptionState()
	require.NoError(t, err)
	require.Len(t, original.Extra, 1, "cache insertion cannot mutate the TLS provider's state")
}

func TestClientSessionSettingsMissingMetadataKeepsTLSResumption(t *testing.T) {
	original := settingsTicket(t, nil, true)
	base := &settingsRecordingCache{ticket: original}
	session := &clientSettingsSession{cache: base}
	got, ok := session.Get("opaque-cache-key")
	require.True(t, ok)
	identity, state, err := got.ResumptionState()
	require.NoError(t, err)
	require.Equal(t, []byte("opaque-ticket"), identity)
	require.False(t, state.EarlyData)
	_, old, err := original.ResumptionState()
	require.NoError(t, err)
	require.True(t, old.EarlyData, "application-owned tickets remain immutable")
}

func TestClientSessionSettingsPendingBoundsAndClose(t *testing.T) {
	base := &settingsRecordingCache{}
	session := &clientSettingsSession{cache: base}
	ticket := settingsTicket(t, nil, true)
	for range maxPendingSettingsTickets + 10 {
		session.Put("key", ticket)
	}
	require.Len(t, session.pending, maxPendingSettingsTickets)
	session.close()
	require.Empty(t, session.pending)
	session.Put("key", ticket)
	session.commitSettings(&settingsFrame{MaxFieldSectionSize: -1})
	require.Empty(t, base.puts)
}

func TestClientSessionSettingsCacheDeletionDoesNotResurrectTickets(t *testing.T) {
	base := &settingsRecordingCache{}
	session := &clientSettingsSession{cache: base}
	session.Put("key", settingsTicket(t, nil, true))
	session.Put("key", nil)
	require.Equal(t, []*tls.ClientSessionState{nil}, base.puts)
	session.commitSettings(&settingsFrame{MaxFieldSectionSize: -1})
	require.Len(t, base.puts, 1)
}

type orderedSettingsCache struct {
	tls.ClientSessionCache
	entered, release chan struct{}
	stored           chan pendingSettingsTicket
	once             sync.Once
}

func (c *orderedSettingsCache) Put(key string, ticket *tls.ClientSessionState) {
	c.once.Do(func() { close(c.entered); <-c.release })
	c.stored <- pendingSettingsTicket{key, ticket}
}

func TestClientSessionSettingsPreserveInsertionOrderAndOpaqueKeys(t *testing.T) {
	base := &orderedSettingsCache{entered: make(chan struct{}), release: make(chan struct{}), stored: make(chan pendingSettingsTicket, 2)}
	session := &clientSettingsSession{cache: base}
	ticket := settingsTicket(t, nil, true)
	session.Put("first opaque key", ticket)
	committed := make(chan struct{})
	go func() { session.commitSettings(&settingsFrame{MaxFieldSectionSize: 4096}); close(committed) }()
	<-base.entered
	inserted := make(chan struct{})
	go func() { session.Put("second opaque key", ticket); close(inserted) }()
	require.Eventually(t, func() bool { session.mutex.Lock(); defer session.mutex.Unlock(); return len(session.pending) == 1 }, time.Second, time.Millisecond)
	close(base.release)
	<-committed
	<-inserted
	require.Equal(t, "first opaque key", (<-base.stored).key)
	require.Equal(t, "second opaque key", (<-base.stored).key)
}

func TestResumedSettingsCompatibility(t *testing.T) {
	settings := func(capacity, blocked uint64, limit int64) *settingsFrame {
		return &settingsFrame{MaxFieldSectionSize: limit, Other: orderedTestSettings(map[uint64]uint64{1: capacity, 7: blocked})}
	}
	for _, tc := range []struct {
		name         string
		old, current *settingsFrame
		code         ErrCode
	}{
		{"same", settings(4096, 16, 100), settings(4096, 16, 100), 0},
		{"larger limits", settings(4096, 16, 100), settings(4096, 32, 200), 0},
		{"enable table", settings(0, 0, -1), settings(4096, 16, 100), 0},
		{"table decrease", settings(4096, 16, 100), settings(1024, 16, 100), ErrCodeQPACKDecoderStreamError},
		{"table increase", settings(4096, 16, 100), settings(8192, 16, 100), ErrCodeQPACKDecoderStreamError},
		{"blocked decrease", settings(4096, 16, 100), settings(4096, 1, 100), ErrCodeSettingsError},
		{"field limit decrease", settings(0, 0, 100), settings(0, 0, 99), ErrCodeSettingsError},
		{"omitted nondefault field limit", settings(0, 0, 100), settings(0, 0, -1), ErrCodeSettingsError},
		{"omitted explicit zero limit", settings(0, 0, 0), settings(0, 0, -1), ErrCodeSettingsError},
		{"datagrams disabled", &settingsFrame{MaxFieldSectionSize: -1, Datagram: true}, settings(0, 0, -1), ErrCodeSettingsError},
		{"connect disabled", &settingsFrame{MaxFieldSectionSize: -1, ExtendedConnect: true}, settings(0, 0, -1), ErrCodeSettingsError},
		{"unknown changes ignored", &settingsFrame{MaxFieldSectionSize: -1, Other: orderedTestSettings(map[uint64]uint64{1337: 9})}, settings(0, 0, -1), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, err := checkResumedSettings(tc.old, tc.current)
			require.Equal(t, tc.code, code)
			require.Equal(t, tc.code != 0, err != nil)
		})
	}
}

func TestResumedCapacityErrorPolicyBounds(t *testing.T) {
	for _, code := range []ErrCode{0, ErrCodeSettingsError, ErrCodeQPACKDecoderStreamError, 1 << 62} {
		config := &QPACKConfig{ResumptionErrorCode: func(old, current uint64) ErrCode {
			require.EqualValues(t, 4096, old)
			require.EqualValues(t, 8192, current)
			return code
		}}
		want := code
		if want == 0 {
			want = ErrCodeQPACKDecoderStreamError
		}
		if want == 1<<62 {
			want = ErrCodeInternalError
		}
		require.Equal(t, want, resumedCapacityErrorCode(config, 4096, 8192))
	}
	require.Equal(t, ErrCodeQPACKDecoderStreamError, resumedCapacityErrorCode(&QPACKConfig{}, 4096, 1024))
}

func TestClientSessionSettingsEncodingIsIndependentOfPointers(t *testing.T) {
	sf := &settingsFrame{MaxFieldSectionSize: 0, Other: g.NewMapOrd[uint64, uint64]()}
	encoded := encodeClientSettings(sf)
	parsed, ok := clientSettingsFromExtra([][]byte{encoded})
	require.True(t, ok)
	require.Zero(t, parsed.MaxFieldSectionSize)
	require.True(t, bytes.HasPrefix(encoded, []byte(clientSettingsPrefix)))
}
