package http3

import (
	"github.com/enetx/quic-go"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTransportCompatibleVersionConfiguration(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		tr := &Transport{QUICConfig: &quic.Config{Versions: []quic.Version{quic.Version1, quic.Version2}, ClientHandshake: &quic.ClientHandshake{CompatibleVersionNegotiation: enabled}}}
		err := tr.init()
		if enabled {
			require.NoError(t, err)
		} else {
			require.ErrorContains(t, err, "single QUIC version")
		}
		require.NoError(t, tr.Close())
	}
}
