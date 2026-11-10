package quic

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/testdata"
	"github.com/stretchr/testify/require"
)

func TestCompatibleVersionWithSeparatePacketNumberSpaces(t *testing.T) {
	for _, tc := range []struct {
		name     string
		original Version
		options  compatiblePeerOptions
	}{
		{"v1-v2", Version1, compatiblePeerOptions{target: Version2}},
		{"v2-v1", Version2, compatiblePeerOptions{target: Version1}},
		{"retry-loss-reorder", Version1, compatiblePeerOptions{target: Version2, retry: true, dropFirst: true, reorder: true, ackFirst: true}},
		{"vn-retry-compatible", Version1, compatiblePeerOptions{target: Version1, vn: true, available: []Version{Version2}, retry: true, reorder: true, ackFirst: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, peerDone := compatiblePacketPeer(t, tc.options)
			other := Version2
			if tc.original == Version2 {
				other = Version1
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			connection, err := DialAddr(ctx, address, &tls.Config{RootCAs: testdata.GetRootCA(), ServerName: "localhost", NextProtos: []string{"compatible-test"}}, &Config{
				Versions: []Version{tc.original, other}, ClientHandshake: &ClientHandshake{
					CompatibleVersionNegotiation: true, SeparatePacketNumberSpaces: true, DisablePacketNumberSkipping: true,
					CongestionControl: CongestionControlCubic, SlowStart: SlowStartClassic,
					InitialCongestionWindowPackets: 12, MaxCongestionWindowPackets: -1,
					Pacing: &PacingConfig{Algorithm: PacingLeakyBucket, BurstPackets: 2, LumpyPackets: 1,
						SlowStartGain: 2000, AvoidanceGain: 2000, Granularity: time.Millisecond},
				},
			})
			require.NoError(t, err)
			defer connection.CloseWithError(0, "")
			require.Equal(t, tc.options.target, connection.ConnectionState().Version)
			select {
			case err := <-peerDone:
				require.NoError(t, err)
			case <-ctx.Done():
				t.Fatal("peer did not authenticate client Finished")
			}
		})
	}
}
