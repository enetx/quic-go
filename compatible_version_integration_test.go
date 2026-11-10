package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/handshake"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/qerr"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

// This small packet peer drives the actual client connection, packet queues,
// retransmissions and TLS verification. It uses native TLS with explicitly
// selected packet keys; it is not a second implementation of version selection.
// Independent implementation checks additionally use official aioquic.
type compatiblePeerOptions struct {
	target                                            Version
	retry, ackFirst, reorder, dropFirst, corruptFirst bool
	vn                                                bool
	vnVersion                                         Version
	available                                         []Version
	wrongChosen, omitInfo                             bool
}

func compatiblePacketPeer(t *testing.T, options compatiblePeerOptions) (string, <-chan error) {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { udp.Close() })
	done := make(chan error, 1)
	go func() { done <- serveCompatiblePeer(udp, options) }()
	return udp.LocalAddr().String(), done
}

func serveCompatiblePeer(udp *net.UDPConn, o compatiblePeerOptions) error {
	if o.vnVersion == 0 {
		o.vnVersion = Version2
	}
	udp.SetReadDeadline(time.Now().Add(5 * time.Second))
	serverID := protocol.ParseConnectionID([]byte("serverid"))
	var peerAddress *net.UDPAddr
	write := func(data []byte) (int, error) { return udp.WriteToUDP(data, peerAddress) }
	var originalID, keyID, clientID protocol.ConnectionID
	var originalVersion Version
	var server handshake.CryptoSetup
	defer func() {
		if server != nil {
			server.Close()
		}
	}()
	streams := map[protocol.EncryptionLevel]*cryptoStream{protocol.EncryptionInitial: newCryptoStream(), protocol.EncryptionHandshake: newCryptoStream()}
	var initialData, handshakeData []byte
	var initialPN, handshakePN protocol.PacketNumber
	var highestClientInitial protocol.PacketNumber
	var initialOpener handshake.LongHeaderOpener
	retrySent, vnSent, flightSent := false, false, false
	sendLong := func(typ protocol.PacketType, version Version, plain []byte, sealer handshake.LongHeaderSealer) error {
		pn := initialPN
		if typ == protocol.PacketTypeHandshake {
			pn = handshakePN
			handshakePN++
		} else {
			initialPN++
		}
		hdr := &wire.ExtendedHeader{Header: wire.Header{Type: typ, Version: version, SrcConnectionID: serverID, DestConnectionID: clientID}, PacketNumber: pn, PacketNumberLen: 2}
		hdr.Length = protocol.ByteCount(2 + len(plain) + sealer.Overhead())
		raw, err := hdr.Append(make([]byte, 0, 1500), version)
		if err != nil {
			return err
		}
		if typ == protocol.PacketTypeInitial && len(raw)+len(plain)+sealer.Overhead() < 1200 {
			padding := 1200 - len(raw) - len(plain) - sealer.Overhead()
			plain = append(append([]byte(nil), plain...), make([]byte, padding)...)
			hdr.Length = protocol.ByteCount(2 + len(plain) + sealer.Overhead())
			raw, err = hdr.Append(raw[:0], version)
			if err != nil {
				return err
			}
		}
		offset := len(raw)
		raw = append(raw, plain...)
		raw = (&packetPacker{}).encryptPacket(raw, sealer, pn, protocol.ByteCount(offset), 2)
		if o.corruptFirst && typ == protocol.PacketTypeInitial && version == o.target {
			o.corruptFirst = false
			corrupt := append([]byte(nil), raw...)
			corrupt[len(corrupt)-1] ^= 1
			if _, err = write(corrupt); err != nil {
				return err
			}
		}
		_, err = write(raw)
		return err
	}
	sendFlight := func() error {
		if o.dropFirst && !flightSent {
			flightSent = true
			return nil
		}
		flightSent = true
		if o.ackFirst {
			o.ackFirst = false
			seal, _ := handshake.NewInitialAEAD(keyID, protocol.PerspectiveServer, originalVersion)
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: highestClientInitial}}}
			plain, err := ack.Append(nil, originalVersion)
			if err != nil {
				return err
			}
			if err = sendLong(protocol.PacketTypeInitial, originalVersion, plain, seal); err != nil {
				return err
			}
		}
		sendCrypto := func(level protocol.EncryptionLevel, data []byte) error {
			typ := protocol.PacketTypeInitial
			seal, err := server.GetInitialSealer()
			if level == protocol.EncryptionHandshake {
				typ = protocol.PacketTypeHandshake
				seal, err = server.GetHandshakeSealer()
			}
			if err != nil {
				return err
			}
			for offset := 0; offset < len(data); {
				end := min(offset+900, len(data))
				plain, err := (&wire.CryptoFrame{Offset: protocol.ByteCount(offset), Data: data[offset:end]}).Append(nil, o.target)
				if err != nil {
					return err
				}
				if err = sendLong(typ, o.target, plain, seal); err != nil {
					return err
				}
				offset = end
			}
			return nil
		}
		if o.reorder {
			if err := sendCrypto(protocol.EncryptionHandshake, handshakeData); err != nil {
				return err
			}
		}
		if err := sendCrypto(protocol.EncryptionInitial, initialData); err != nil {
			return err
		}
		if !o.reorder {
			return sendCrypto(protocol.EncryptionHandshake, handshakeData)
		}
		return nil
	}
	parser := wire.NewFrameParser(false, false, false)
	buffer := make([]byte, 65536)
	for {
		n, remote, err := udp.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		peerAddress = remote
		data := append([]byte(nil), buffer[:n]...)
		for len(data) > 0 {
			hdr, packetData, rest, err := wire.ParsePacket(data)
			if err != nil {
				break
			}
			data = rest
			if hdr.Type == protocol.PacketType0RTT {
				continue
			}
			if o.vn && !vnSent {
				vnSent = true
				raw := wire.ComposeVersionNegotiation(protocol.ArbitraryLenConnectionID(hdr.SrcConnectionID.Bytes()), protocol.ArbitraryLenConnectionID(hdr.DestConnectionID.Bytes()), []Version{o.vnVersion})
				if _, err = write(raw); err != nil {
					return err
				}
				break
			}
			if o.vn && server == nil && hdr.Version != o.vnVersion {
				continue
			}
			if !originalID.Valid() {
				originalID = hdr.DestConnectionID
				originalVersion = hdr.Version
				clientID = hdr.SrcConnectionID
			}
			if o.retry && !retrySent {
				retrySent = true
				raw, err := (&wire.ExtendedHeader{Header: wire.Header{Type: protocol.PacketTypeRetry, Version: hdr.Version, SrcConnectionID: serverID, DestConnectionID: hdr.SrcConnectionID, Token: []byte("retry")}}).Append(nil, hdr.Version)
				if err != nil {
					return err
				}
				raw = append(raw, handshake.GetRetryIntegrityTag(raw, originalID, hdr.Version)[:]...)
				if _, err = write(raw); err != nil {
					return err
				}
				break
			}
			if o.retry && hdr.DestConnectionID != serverID {
				continue
			}
			if hdr.Type == protocol.PacketTypeInitial && initialOpener == nil {
				keyID = hdr.DestConnectionID
				_, initialOpener = handshake.NewInitialAEAD(keyID, protocol.PerspectiveServer, hdr.Version)
				params := &wire.TransportParameters{InitialSourceConnectionID: serverID, OriginalDestinationConnectionID: originalID, ActiveConnectionIDLimit: 2, InitialMaxData: 1 << 20, InitialMaxStreamDataBidiLocal: 1 << 20, InitialMaxStreamDataBidiRemote: 1 << 20, MaxUDPPayloadSize: 1500, MaxDatagramFrameSize: protocol.InvalidByteCount}
				if o.retry {
					params.RetrySourceConnectionID = serverID
				}
				chosen := o.target
				if o.wrongChosen {
					chosen = originalVersion
				}
				available := o.available
				if available == nil {
					available = []Version{Version1, Version2}
				}
				if !o.omitInfo {
					params.VersionInformation = &wire.VersionInformation{Chosen: chosen, Available: available}
				}
				conf := testdata.GetTLSConfig()
				conf.NextProtos = []string{"compatible-test"}
				server = handshake.NewCryptoSetupServer(keyID, udp.LocalAddr(), remote, params, conf, false, utils.NewRTTStats(), nil, utils.DefaultLogger, o.target)
				if err = server.StartHandshake(context.Background()); err != nil {
					return err
				}
			}
			if server == nil {
				continue
			}
			level := protocol.EncryptionInitial
			opener := initialOpener
			if hdr.Type == protocol.PacketTypeHandshake {
				level = protocol.EncryptionHandshake
				opener, err = server.GetHandshakeOpener()
				if err != nil {
					continue
				}
			}
			extended, plain, err := (&packetUnpacker{}).unpackLongHeaderPacket(opener, hdr, packetData)
			if err != nil {
				continue
			}
			if level == protocol.EncryptionInitial {
				highestClientInitial = max(highestClientInitial, extended.PacketNumber)
			}

			for len(plain) > 0 {
				typ, l, err := parser.ParseType(plain, level)
				if err == io.EOF {
					break
				}
				if err != nil {
					return err
				}
				plain = plain[l:]
				if typ.IsAckFrameType() {
					_, l, err = parser.ParseAckFrame(typ, plain, level, hdr.Version)
					if err != nil {
						return err
					}
					plain = plain[l:]
					continue
				}
				frame, l, err := parser.ParseLessCommonFrame(typ, plain, hdr.Version)
				if err != nil {
					return err
				}
				plain = plain[l:]
				if frame, ok := frame.(*wire.CryptoFrame); ok {
					if err = streams[level].HandleCryptoFrame(frame); err != nil {
						return err
					}
					for {
						message := streams[level].GetCryptoData()
						if message == nil {
							break
						}
						if err = server.HandleMessage(message, level); err != nil {
							return err
						}
					}
				}
			}
			for {
				event := server.NextEvent()
				if event.Kind == handshake.EventNoEvent {
					break
				}
				switch event.Kind {
				case handshake.EventWriteInitialData:
					initialData = append(initialData, event.Data...)
				case handshake.EventWriteHandshakeData:
					handshakeData = append(handshakeData, event.Data...)
				case handshake.EventHandshakeComplete:
					return nil
				}
			}
			if level == protocol.EncryptionInitial && len(initialData) > 0 {
				if err = sendFlight(); err != nil {
					return err
				}
			}
		}
	}
}

func TestCompatibleVersionRealConnection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		original Version
		options  compatiblePeerOptions
		failure  bool
	}{
		{"same-v1-old-server", Version1, compatiblePeerOptions{target: Version1, omitInfo: true}, false},
		{"same-v2-old-server", Version2, compatiblePeerOptions{target: Version2, omitInfo: true}, false},
		{"v1-v2", Version1, compatiblePeerOptions{target: Version2}, false},
		{"v2-v1", Version2, compatiblePeerOptions{target: Version1}, false},
		{"retry", Version1, compatiblePeerOptions{target: Version2, retry: true}, false},
		{"old-ack", Version1, compatiblePeerOptions{target: Version2, ackFirst: true}, false},
		{"reordered", Version1, compatiblePeerOptions{target: Version2, reorder: true}, false},
		{"lost-flight", Version1, compatiblePeerOptions{target: Version2, dropFirst: true}, false},
		{"retry-loss-reorder", Version1, compatiblePeerOptions{target: Version2, retry: true, dropFirst: true, reorder: true, ackFirst: true}, false},
		{"corrupt-candidate", Version1, compatiblePeerOptions{target: Version2, corruptFirst: true}, false},
		{"wrong-authenticated-version", Version1, compatiblePeerOptions{target: Version2, wrongChosen: true}, true},
		{"missing-authenticated-version", Version1, compatiblePeerOptions{target: Version2, omitInfo: true}, true},
		{"vn-v2", Version1, compatiblePeerOptions{target: Version2, vn: true, available: []Version{Version2}}, false},
		{"vn-v1-old-server", Version2, compatiblePeerOptions{target: Version1, vn: true, vnVersion: Version1, omitInfo: true}, false},
		{"vn-then-compatible", Version1, compatiblePeerOptions{target: Version1, vn: true, available: []Version{Version2}}, false},
		{"vn-retry-compatible", Version1, compatiblePeerOptions{target: Version1, vn: true, available: []Version{Version2}, retry: true, reorder: true, ackFirst: true}, false},
		{"forged-vn", Version1, compatiblePeerOptions{target: Version2, vn: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, peerDone := compatiblePacketPeer(t, tc.options)
			other := Version1
			if tc.original == Version1 {
				other = Version2
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := DialAddr(ctx, addr, &tls.Config{RootCAs: testdata.GetRootCA(), ServerName: "localhost", NextProtos: []string{"compatible-test"}}, &Config{Versions: []Version{tc.original, other}, ClientHandshake: &ClientHandshake{CompatibleVersionNegotiation: true}})
			if tc.failure {
				var transport *TransportError
				require.ErrorAs(t, err, &transport)
				require.Equal(t, qerr.VersionNegotiationErrorCode, transport.ErrorCode)
				return
			}
			require.NoError(t, err)
			defer conn.CloseWithError(0, "")
			require.Equal(t, tc.options.target, conn.ConnectionState().Version)
			select {
			case err := <-peerDone:
				require.NoError(t, err)
			case <-ctx.Done():
				t.Fatal(fmt.Errorf("server Finished was not verified: %w", ctx.Err()))
			}
		})
	}
}

func TestCompatibleVersionMalformedAuthenticatedInformation(t *testing.T) {
	addr, _ := compatiblePacketPeer(t, compatiblePeerOptions{target: Version2, available: []Version{0}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := DialAddr(ctx, addr, &tls.Config{RootCAs: testdata.GetRootCA(), ServerName: "localhost", NextProtos: []string{"compatible-test"}}, &Config{Versions: []Version{Version1, Version2}, ClientHandshake: &ClientHandshake{CompatibleVersionNegotiation: true}})
	var transport *TransportError
	require.ErrorAs(t, err, &transport)
	require.Equal(t, qerr.TransportParameterError, transport.ErrorCode)
}

func TestCompatibleVersionStillVerifiesCertificate(t *testing.T) {
	addr, _ := compatiblePacketPeer(t, compatiblePeerOptions{target: Version2})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := DialAddr(ctx, addr, &tls.Config{RootCAs: testdata.GetRootCA(), ServerName: "wrong.example", NextProtos: []string{"compatible-test"}}, &Config{Versions: []Version{Version1, Version2}, ClientHandshake: &ClientHandshake{CompatibleVersionNegotiation: true}})
	require.ErrorContains(t, err, "certificate")
}
