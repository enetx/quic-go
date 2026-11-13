package quic

import (
	"errors"
	"testing"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/qerr"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/quic-go/transportparams"
	"github.com/stretchr/testify/require"
)

func TestPeerTransportParameterUsesOnlyVerifiedCurrentHandshake(t *testing.T) {
	raw := []byte{0, 0, 15, 0} // Required server connection IDs, both empty.
	raw = quicvarint.Append(raw, 0x3128)
	raw = quicvarint.Append(raw, 8)
	raw = append(raw, "ORIGNOIP"...)
	for _, capture := range []bool{false, true} {
		var ids []uint64
		if capture {
			ids = []uint64{0x3128}
		}
		parameters := &wire.TransportParameters{CapturePeerParameters: ids}
		require.NoError(t, parameters.Unmarshal(raw, protocol.PerspectiveServer))
		ready := make(chan struct{})
		c := &Conn{handshakeCompleteChan: ready, peerParams: parameters}
		_, found := c.PeerTransportParameter(0x3128)
		require.False(t, found, "early ticket/readiness cannot authorize coalescing")
		close(ready)
		value, found := c.PeerTransportParameter(0x3128)
		require.Equal(t, capture, found)
		if capture {
			require.Equal(t, "ORIGNOIP", string(value))
			value[0] = '!'
			again, _ := c.PeerTransportParameter(0x3128)
			require.Equal(t, "ORIGNOIP", string(again), "snapshots must not expose internal bytes")
		}
		ticket := parameters.MarshalForSessionTicket(nil)
		restored := &wire.TransportParameters{CapturePeerParameters: ids}
		require.NoError(t, restored.UnmarshalFromSessionTicket(ticket))
		require.Empty(t, restored.UnknownParameters, "an old connection's option must not authorize a new one")
	}
}

func TestPeerTransportParameterValidatorCannotMutateOrPublishRejectedState(t *testing.T) {
	failure := errors.New("application rejected extension")
	calls := 0
	tc := newClientTestConnection(t, nil, &Config{ValidatePeerTransportParameters: func(parameters []transportparams.Parameter) error {
		calls++
		require.Equal(t, "NOIP", string(parameters[0].Value))
		parameters[0].Value[0] = '!'
		return failure
	}}, true)
	parameters := &wire.TransportParameters{
		OriginalDestinationConnectionID: tc.destConnID,
		InitialSourceConnectionID:       tc.conn.handshakeDestConnID,
		UnknownParameters:               []transportparams.Parameter{{ID: 0x3128, Value: []byte("NOIP")}},
	}
	old := tc.conn.peerParams
	err := tc.conn.handleTransportParameters(parameters)
	var transportError *qerr.TransportError
	require.ErrorAs(t, err, &transportError)
	require.Equal(t, qerr.TransportParameterError, transportError.ErrorCode)
	require.Equal(t, failure.Error(), transportError.ErrorMessage)
	require.Same(t, old, tc.conn.peerParams)
	require.Equal(t, "NOIP", string(parameters.UnknownParameters[0].Value))
	require.Equal(t, 1, calls)
	// Restoring a ticket must not invoke a validator for a previous handshake.
	tc.conn.restoreTransportParameters(&wire.TransportParameters{ActiveConnectionIDLimit: 2})
	require.Equal(t, 1, calls)
}

func TestExtensionParameterConfigurationIsClonedAndValidated(t *testing.T) {
	config := &Config{
		PeerTransportParameterIDs: []uint64{0x3128},
		ServerTransportParameters: &transportparams.Layout{Additional: []transportparams.Parameter{{ID: 0x3128, Value: []byte("NOIP")}}},
	}
	for _, clone := range []*Config{config.Clone(), populateConfig(config)} {
		clone.PeerTransportParameterIDs[0] = 42
		clone.ServerTransportParameters.Additional[0].Value[0] = '!'
		require.EqualValues(t, 0x3128, config.PeerTransportParameterIDs[0])
		require.Equal(t, "NOIP", string(config.ServerTransportParameters.Additional[0].Value))
	}
	require.NoError(t, validateConfig(config))
	require.Error(t, validateConfig(&Config{PeerTransportParameterIDs: []uint64{uint64(quicvarint.Max) + 1}}))
	require.Error(t, validateConfig(&Config{ServerTransportParameters: &transportparams.Layout{Additional: []transportparams.Parameter{{ID: 1}}}}))
}
