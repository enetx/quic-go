package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"testing"

	"github.com/enetx/quic-go/internal/handshake"
	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/qerr"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/enetx/quic-go/transportparams"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func compatibleTestConn(t *testing.T, chosen protocol.Version) *Conn {
	t.Helper()
	c := &Conn{version: chosen, perspective: protocol.PerspectiveClient,
		config:         populateConfig(&Config{Versions: []Version{Version1, Version2}, ClientHandshake: &ClientHandshake{CompatibleVersionNegotiation: true}}),
		origDestConnID: protocol.ParseConnectionID([]byte("original")),
	}
	p := &wire.TransportParameters{ActiveConnectionIDLimit: 2, MaxDatagramFrameSize: protocol.InvalidByteCount}
	require.NoError(t, c.configureVersionInformation(p))
	cs := handshake.NewCryptoSetupClient(c.origDestConnID, p, &tls.Config{}, false, utils.NewRTTStats(), nil, utils.DefaultLogger, chosen)
	t.Cleanup(func() { cs.Close() })
	c.cryptoStreamHandler = cs
	return c
}

func compatibleInitialPacket(t *testing.T, c *Conn, version protocol.Version, keyID protocol.ConnectionID) (*wire.Header, []byte) {
	t.Helper()
	sealer, _ := handshake.NewInitialAEAD(keyID, protocol.PerspectiveServer, version)
	payload := []byte{1, 0, 0, 0}
	hdr := &wire.ExtendedHeader{Header: wire.Header{Type: protocol.PacketTypeInitial, Version: version, SrcConnectionID: protocol.ParseConnectionID([]byte("server")), DestConnectionID: protocol.ParseConnectionID([]byte("client")), Length: protocol.ByteCount(2 + len(payload) + sealer.Overhead())}, PacketNumber: 3, PacketNumberLen: 2}
	raw, err := hdr.Append(make([]byte, 0, 1500), version)
	require.NoError(t, err)
	offset := len(raw)
	raw = append(raw, payload...)
	raw = (&packetPacker{}).encryptPacket(raw, sealer, hdr.PacketNumber, protocol.ByteCount(offset), 2)
	parsed, _, _, err := wire.ParsePacket(raw)
	require.NoError(t, err)
	return parsed, raw
}

func TestCompatibleVersionAuthenticationAndState(t *testing.T) {
	for _, from := range []protocol.Version{protocol.Version1, protocol.Version2} {
		to := protocol.Version1
		if from == to {
			to = protocol.Version2
		}
		c := compatibleTestConn(t, from)
		c.baseTokenStoreKey = "origin"
		c.tokenStoreKey = versionedTokenKey("origin", from)
		hdr, raw := compatibleInitialPacket(t, c, to, c.origDestConnID)
		intact := bytes.Clone(raw)
		corrupt := bytes.Clone(raw)
		corrupt[len(corrupt)-1] ^= 1
		require.False(t, c.acceptCompatibleVersion(hdr, corrupt))
		require.Equal(t, from, c.version)
		require.True(t, c.acceptCompatibleVersion(hdr, raw))
		require.Equal(t, to, c.version)
		require.Equal(t, intact, raw, "candidate verification must not mutate the real packet")
		require.Equal(t, versionedTokenKey("origin", to), c.tokenStoreKey)
		packet, err := newPacketUnpacker(c.cryptoStreamHandler.(handshake.CryptoSetup), 6).UnpackLongHeader(hdr, raw)
		require.NoError(t, err)
		require.EqualValues(t, 3, packet.hdr.PacketNumber)
		require.False(t, c.acceptCompatibleVersion(&wire.Header{Type: protocol.PacketTypeInitial, Version: from}, nil), "cannot switch a second time")
		require.NoError(t, c.checkVersionInformation(&wire.TransportParameters{VersionInformation: &wire.VersionInformation{Chosen: to, Available: []Version{Version1, Version2}}}))
		require.Error(t, c.checkVersionInformation(&wire.TransportParameters{}))
		require.Error(t, c.checkVersionInformation(&wire.TransportParameters{VersionInformation: &wire.VersionInformation{Chosen: from, Available: []Version{from}}}))
	}
}

func TestCompatibleVersionCandidateGuards(t *testing.T) {
	for _, mode := range []string{"disabled", "not-offered", "confirmed", "source-id", "wrong-key", "retry", "zero-rtt", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			c := compatibleTestConn(t, protocol.Version1)
			keyID := c.origDestConnID
			if mode == "wrong-key" {
				keyID = protocol.ParseConnectionID([]byte("wrongkey"))
			}
			hdr, raw := compatibleInitialPacket(t, c, protocol.Version2, keyID)
			switch mode {
			case "disabled":
				c.compatibleVersion = nil
			case "not-offered":
				c.compatibleVersion.offered.Available = []Version{Version1}
			case "confirmed":
				c.compatibleVersion.confirmed = true
			case "source-id":
				c.receivedFirstPacket = true
				c.handshakeDestConnID = protocol.ParseConnectionID([]byte("other"))
			case "retry":
				hdr.Type = protocol.PacketTypeRetry
			case "zero-rtt":
				hdr.Type = protocol.PacketType0RTT
			case "unknown":
				hdr.Version = 0x12345678
			}
			require.False(t, c.acceptCompatibleVersion(hdr, raw))
			require.Equal(t, Version1, c.version)
		})
	}
	c := compatibleTestConn(t, Version1)
	require.True(t, c.acceptCompatibleVersion(&wire.Header{Type: protocol.PacketTypeHandshake, Version: Version2}, nil))
	require.Equal(t, Version1, c.version, "an early Handshake is queued without committing a version")
}

func TestCompatibleVersionDowngradeChecks(t *testing.T) {
	for _, tc := range []struct {
		name               string
		chosen, negotiated Version
		vn                 bool
		info               *wire.VersionInformation
		valid              bool
	}{
		{"v1-old-server", Version1, Version1, false, nil, true},
		{"v2-direct-old-server", Version2, Version2, false, nil, true},
		{"v2-switch-missing-info", Version1, Version2, false, nil, false},
		{"vn-v1-implicit", Version1, Version1, true, nil, true},
		{"vn-v2-missing-info", Version2, Version2, true, nil, false},
		{"vn-v2-empty", Version2, Version2, true, &wire.VersionInformation{Chosen: Version2}, false},
		{"vn-downgrade", Version2, Version2, true, &wire.VersionInformation{Chosen: Version2, Available: []Version{Version1, Version2}}, false},
		{"vn-v2-only", Version2, Version2, true, &wire.VersionInformation{Chosen: Version2, Available: []Version{Version2}}, true},
		{"vn-then-compatible", Version2, Version1, true, &wire.VersionInformation{Chosen: Version1, Available: []Version{Version2}}, true},
		{"unoffered", Version1, Version1, false, &wire.VersionInformation{Chosen: 0x12345678}, false},
		{"header-mismatch", Version1, Version1, false, &wire.VersionInformation{Chosen: Version2}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := compatibleTestConn(t, tc.chosen)
			c.version = tc.negotiated
			c.versionNegotiated = tc.vn
			err := c.checkVersionInformation(&wire.TransportParameters{VersionInformation: tc.info})
			if tc.valid {
				require.NoError(t, err)
			} else {
				var transportErr *qerr.TransportError
				require.ErrorAs(t, err, &transportErr)
				require.Equal(t, qerr.VersionNegotiationErrorCode, transportErr.ErrorCode)
			}
		})
	}
}

func TestCompatibleVersionLayoutValidationAndSnapshot(t *testing.T) {
	for _, bad := range [][]Version{{Version1, Version2}, {Version2, Version2}, {Version1, Version1, 0}, {Version1, Version1, 0x12345678}} {
		var data []byte
		for _, v := range bad {
			data = binary.BigEndian.AppendUint32(data, uint32(v))
		}
		c := compatibleTestConn(t, Version1)
		p := &wire.TransportParameters{ClientLayout: &transportparams.Layout{Additional: []transportparams.Parameter{{ID: 17, Value: data}}}}
		require.Error(t, c.configureVersionInformation(p))
	}
	c := compatibleTestConn(t, Version1)
	data := binary.BigEndian.AppendUint32(nil, uint32(Version1))
	data = binary.BigEndian.AppendUint32(data, 0x1a2a3a4a)
	data = binary.BigEndian.AppendUint32(data, uint32(Version2))
	data = binary.BigEndian.AppendUint32(data, uint32(Version1))
	layout := &transportparams.Layout{Order: []uint64{15, 17}, Additional: []transportparams.Parameter{{ID: 17, Value: data}}}
	p := &wire.TransportParameters{ClientLayout: layout.Clone()}
	require.NoError(t, c.configureVersionInformation(p))
	require.Len(t, layout.Additional, 1)
	require.Empty(t, p.ClientLayout.Additional)
	require.Equal(t, []Version{0x1a2a3a4a, Version2, Version1}, p.VersionInformation.Available)
	data[4] = 0
	require.EqualValues(t, 0x1a2a3a4a, p.VersionInformation.Available[0])
}

func TestCompatibleZeroRTTPacketKeepsOriginalVersion(t *testing.T) {
	for _, original := range []Version{Version1, Version2} {
		negotiated := Version1
		if original == Version1 {
			negotiated = Version2
		}
		ctrl := gomock.NewController(t)
		p := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
		p.packer.zeroRTTVersion = original
		p.pnManager.EXPECT().PeekPacketNumber(protocol.PacketNumberSpaceAppData).Return(protocol.PacketNumber(4), protocol.PacketNumberLen2)
		hdr := p.packer.getLongHeader(protocol.Encryption0RTT, negotiated)
		require.Equal(t, original, hdr.Version)
		sealer, _ := handshake.NewInitialAEAD(protocol.ConnectionID{}, protocol.PerspectiveClient, original)
		buffer := getPacketBuffer()
		defer buffer.Release()
		packet, err := p.packer.appendLongHeaderPacket(buffer, hdr, payload{}, 4, sealer, negotiated)
		require.NoError(t, err)
		wireHeader, _, _, err := wire.ParsePacket(buffer.Data)
		require.NoError(t, err)
		require.Equal(t, original, wireHeader.Version)
		require.Equal(t, protocol.PacketType0RTT, wireHeader.Type)
		require.Equal(t, original, packet.header.Version)
	}
}

func TestFirstServerCryptoLocksCompatibleVersion(t *testing.T) {
	tc := newClientTestConnection(t, nil, &Config{Versions: []Version{Version1, Version2}, ClientHandshake: &ClientHandshake{CompatibleVersionNegotiation: true}}, false)
	c := tc.conn.Conn
	cs := c.cryptoStreamHandler.(handshake.CryptoSetup)
	require.NoError(t, cs.StartHandshake(context.Background()))
	defer cs.Close()
	for cs.NextEvent().Kind != handshake.EventNoEvent {
	}
	// Empty CRYPTO does not fix a version; a single ServerHello byte does,
	// without waiting for a complete TLS message or derived Handshake keys.
	require.NoError(t, c.handleCryptoFrame(&wire.CryptoFrame{}, protocol.EncryptionInitial, monotime.Now()))
	require.False(t, c.compatibleVersion.confirmed)
	require.NoError(t, c.handleCryptoFrame(&wire.CryptoFrame{Data: []byte{2}}, protocol.EncryptionInitial, monotime.Now()))
	require.True(t, c.compatibleVersion.confirmed)
	require.False(t, c.acceptCompatibleVersion(&wire.Header{Type: protocol.PacketTypeInitial, Version: Version2}, nil))
}

func TestCompatibleVersionScopesNewTokenCache(t *testing.T) {
	store := NewLRUTokenStore(4, 4)
	const host = "quic-go.net"
	legacy := &ClientToken{data: []byte("legacy")}
	one := &ClientToken{data: []byte("version one")}
	store.Put(host, legacy)
	store.Put(versionedTokenKey(host, Version1), one)
	tc := newClientTestConnection(t, nil, &Config{Versions: []Version{Version1, Version2}, TokenStore: store, ClientHandshake: &ClientHandshake{CompatibleVersionNegotiation: true}}, false)
	c := tc.conn.Conn
	defer c.cryptoStreamHandler.(handshake.CryptoSetup).Close()
	require.Nil(t, store.Pop(versionedTokenKey(host, Version1)), "the original-version token was consumed")
	require.Same(t, legacy, store.Pop(host), "unscoped tokens must not be reused by a version-aware client")
	hdr, raw := compatibleInitialPacket(t, c, Version2, c.origDestConnID)
	require.True(t, c.acceptCompatibleVersion(hdr, raw))
	require.NoError(t, c.handleNewTokenFrame(&wire.NewTokenFrame{Token: []byte("version two")}))
	require.Equal(t, []byte("version two"), store.Pop(versionedTokenKey(host, Version2)).data)
	require.Nil(t, store.Pop(versionedTokenKey(host, Version1)))
}
