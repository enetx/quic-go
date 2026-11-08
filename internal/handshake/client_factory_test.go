package handshake

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/utils"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/enetx/quic-go/tlsquic"
	"github.com/stretchr/testify/require"
)

func TestClientTLSFactoryFailure(t *testing.T) {
	sentinel := errors.New("invalid external template")
	for _, factory := range []tlsquic.NewClient{func(*tls.Config) (tlsquic.Conn, error) { return nil, sentinel }, func(*tls.Config) (tlsquic.Conn, error) { return nil, nil }} {
		client := NewCryptoSetupClient(protocol.ConnectionID{}, &wire.TransportParameters{}, &tls.Config{}, false, utils.NewRTTStats(), nil, utils.DefaultLogger, protocol.Version1, factory)
		require.Error(t, client.StartHandshake(context.Background()))
		require.NoError(t, client.Close())
	}
}
