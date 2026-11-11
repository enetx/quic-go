package handshake

import (
	"crypto/tls"
	"testing"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/qerr"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

type compatibleTLSClient struct {
	CryptoSetup
	target                  protocol.Version
	switched                bool
	beforeEarly, afterEarly LongHeaderSealer
}

func (c *compatibleTLSClient) HandleMessage(data []byte, level protocol.EncryptionLevel) error {
	if level == protocol.EncryptionInitial && !c.switched {
		c.beforeEarly, _ = c.CryptoSetup.Get0RTTSealer()
		if err := c.CryptoSetup.(*cryptoSetup).SwitchVersion(c.target); err != nil {
			return err
		}
		c.afterEarly, _ = c.CryptoSetup.Get0RTTSealer()
		c.switched = true
	}
	return c.CryptoSetup.HandleMessage(data, level)
}

func TestCompatibleVersionTLSKeysAndSessionResumption(t *testing.T) {
	clientConfig, serverConfig := getTLSConfigs()
	clientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(10)
	run := func(original, negotiated protocol.Version, early bool) (*cryptoSetup, *cryptoSetup) {
		t.Helper()
		cp := &wire.TransportParameters{ActiveConnectionIDLimit: 2, CompatibleVersionNegotiation: true, VersionInformation: &wire.VersionInformation{Chosen: original, Available: []protocol.Version{protocol.Version2, protocol.Version1}}}
		sp := &wire.TransportParameters{ActiveConnectionIDLimit: 2, InitialMaxData: 65536, VersionInformation: &wire.VersionInformation{Chosen: negotiated, Available: []protocol.Version{protocol.Version1, protocol.Version2}}}
		client := NewCryptoSetupClient(protocol.ConnectionID{}, cp, clientConfig, early, utils.NewRTTStats(), nil, utils.DefaultLogger, original).(*cryptoSetup)
		server := NewCryptoSetupServer(protocol.ConnectionID{}, nil, nil, sp, serverConfig, true, utils.NewRTTStats(), nil, utils.DefaultLogger, negotiated).(*cryptoSetup)
		t.Cleanup(func() { client.Close(); server.Close() })
		var peer CryptoSetup = client
		var switching *compatibleTLSClient
		if original != negotiated {
			switching = &compatibleTLSClient{CryptoSetup: client, target: negotiated}
			peer = switching
		}
		_, ce, _, se := handshake(t, peer, server)
		require.NoError(t, ce)
		require.NoError(t, se)
		if switching != nil && early && client.ConnectionState().DidResume {
			require.NotNil(t, switching.beforeEarly)
			require.Same(t, switching.beforeEarly, switching.afterEarly)
		}
		require.Equal(t, negotiated, client.version)
		require.Equal(t, negotiated, client.aead.version)
		sealer, err := client.Get1RTTSealer()
		require.NoError(t, err)
		opener, err := server.Get1RTTOpener()
		require.NoError(t, err)
		encrypted := sealer.Seal(nil, []byte("application bytes"), 3, []byte("header"))
		plain, err := opener.Open(nil, encrypted, monotime.Now(), 3, sealer.KeyPhase(), []byte("header"))
		require.NoError(t, err)
		require.Equal(t, []byte("application bytes"), plain)
		return client, server
	}
	// Obtain a v1 ticket, then resume with an original v1 first flight while
	// the server selects v2. Its original-version 0-RTT keys remain usable.
	first, _ := run(protocol.Version1, protocol.Version1, true)
	require.False(t, first.ConnectionState().DidResume)
	client, server := run(protocol.Version1, protocol.Version2, true)
	require.True(t, client.ConnectionState().DidResume)
	require.True(t, server.ConnectionState().Used0RTT)
	saved, ok := clientConfig.ClientSessionCache.Get("quic:6b3343cf:localhost")
	require.True(t, ok)
	_, state, err := saved.ResumptionState()
	require.NoError(t, err)
	storedVersion, ok := SessionVersion(state.Extra)
	require.True(t, ok)
	require.Equal(t, protocol.Version2, storedVersion, "ticket metadata follows the authenticated switch")

	// The ticket issued after switching belongs to v2 and can resume a direct v2 dial.
	direct, _ := run(protocol.Version2, protocol.Version2, true)
	require.True(t, direct.ConnectionState().DidResume)
	// No v2 ticket may be selected for an original v1 dial when its v1 entry is absent.
	clientConfig.ClientSessionCache.Put("quic:00000001:localhost", nil)
	fresh, _ := run(protocol.Version1, protocol.Version1, false)
	require.False(t, fresh.ConnectionState().DidResume)
	// Both compatible directions use the negotiated application key labels.
	run(protocol.Version2, protocol.Version1, false)
}

func TestCompatibleVersionRetryPNAndGuards(t *testing.T) {
	h := newCryptoSetup(protocol.ParseConnectionID([]byte("original")), &wire.TransportParameters{CompatibleVersionNegotiation: true}, utils.NewRTTStats(), nil, utils.DefaultLogger, protocol.PerspectiveClient, protocol.Version1)
	h.initialOpener.(*longHeaderOpener).highestRcvdPN = 5000
	candidate, err := h.InitialOpenerForVersion(protocol.Version2)
	require.NoError(t, err)
	require.Equal(t, h.initialOpener.DecodePacketNumber(3, 1), candidate.DecodePacketNumber(3, 1))
	retryID := protocol.ParseConnectionID([]byte("retry-id"))
	h.ChangeConnectionID(retryID)
	require.NoError(t, h.SwitchVersion(protocol.Version2))
	server, _ := NewInitialAEAD(retryID, protocol.PerspectiveServer, protocol.Version2)
	ciphertext := server.Seal(nil, []byte("after Retry"), 5, []byte("header"))
	plain, err := h.initialOpener.Open(nil, ciphertext, 5, []byte("header"))
	require.NoError(t, err)
	require.Equal(t, []byte("after Retry"), plain)
	require.Error(t, h.SwitchVersion(protocol.Version2), "no repeated switch")
	h.handshakeOpener = h.initialOpener
	require.Error(t, h.SwitchVersion(protocol.Version1), "handshake keys lock the version")
	h.handshakeOpener = nil
	h.initialOpener = nil
	_, err = h.InitialOpenerForVersion(protocol.Version1)
	require.ErrorIs(t, err, ErrKeysDropped)
}

func TestVersionedSessionCacheIsolation(t *testing.T) {
	cache := tls.NewLRUClientSessionCache(10)
	version := protocol.Version1
	scoped := &versionedSessionCache{cache: cache, version: func() protocol.Version { return version }}
	one, two := new(tls.ClientSessionState), new(tls.ClientSessionState)
	scoped.Put("host", one)
	version = protocol.Version2
	_, ok := scoped.Get("host")
	require.False(t, ok)
	scoped.Put("host", two)
	state, ok := scoped.Get("host")
	require.True(t, ok)
	require.Same(t, two, state)
	version = protocol.Version1
	state, ok = scoped.Get("host")
	require.True(t, ok)
	require.Same(t, one, state)
	_, ok = cache.Get("host")
	require.False(t, ok, "native TLS cache keys remain isolated")
	scoped.Put("host", nil)
	_, ok = scoped.Get("host")
	require.False(t, ok)
}

func TestTransportParameterErrorCodeSurvivesTLSWrapper(t *testing.T) {
	err := &qerr.TransportError{ErrorCode: qerr.TransportParameterError, ErrorMessage: "invalid version_information"}
	require.Same(t, err, wrapError(err))
}
