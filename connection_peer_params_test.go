package quic

import (
	"testing"

	"github.com/enetx/quic-go/internal/handshake"
	"github.com/enetx/quic-go/internal/mocks"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestConnection0RTTConcurrentParameterSnapshots(t *testing.T) {
	for _, mode := range []string{"state", "datagram"} {
		t.Run(mode, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			crypto := mocks.NewMockCryptoSetup(ctrl)
			crypto.EXPECT().ConnectionState().Return(handshake.ConnectionState{Used0RTT: true}).AnyTimes()
			tc := newClientTestConnection(t, ctrl, nil, true, connectionOptCryptoSetup(crypto))
			initial := &wire.TransportParameters{OriginalDestinationConnectionID: tc.destConnID, InitialSourceConnectionID: tc.conn.handshakeDestConnID}
			tc.conn.peerParams = initial
			start, done := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(done)
				<-start
				for range 1000 {
					if mode == "state" {
						tc.conn.ConnectionState()
					} else {
						_ = tc.conn.SendDatagram(nil)
					}
				}
			}()
			close(start)
			for range 1000 {
				updated := *initial
				require.NoError(t, tc.conn.handleTransportParameters(&updated))
			}
			<-done
		})
	}
}
