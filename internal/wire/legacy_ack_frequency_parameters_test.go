package wire

import (
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestLegacyMinAckDelayOptInParsing(t *testing.T) {
	for _, value := range [][]byte{{0x43, 0xe8}, {}, {0x40}, {0, 0}, quicvarint.Append(nil, 1<<24), quicvarint.Append(nil, 26000)} {
		data := (&TransportParameters{MaxUDPPayloadSize: 1452, ActiveConnectionIDLimit: 2,
			MaxAckDelay: protocol.DefaultMaxAckDelay, MaxDatagramFrameSize: protocol.InvalidByteCount}).Marshal(protocol.PerspectiveServer)
		data = quicvarint.Append(data, uint64(legacyMinAckDelayParameterID))
		data = quicvarint.Append(data, uint64(len(value)))
		data = append(data, value...)
		var disabled TransportParameters
		require.NoError(t, disabled.Unmarshal(data, protocol.PerspectiveServer), "disabled mode keeps unknown-parameter behavior")
		require.Nil(t, disabled.LegacyMinAckDelay)
		enabled := TransportParameters{ParseLegacyAckFrequency: true}
		err := enabled.Unmarshal(data, protocol.PerspectiveServer)
		if string(value) == string([]byte{0x43, 0xe8}) {
			require.NoError(t, err)
			require.Equal(t, time.Millisecond, *enabled.LegacyMinAckDelay)
		} else {
			require.Error(t, err)
		}
	}
}

func TestLegacyMinAckDelayIsNotRememberedForZeroRTT(t *testing.T) {
	minimum := time.Millisecond
	params := TransportParameters{ParseLegacyAckFrequency: true, LegacyMinAckDelay: &minimum, ActiveConnectionIDLimit: 2}
	var restored TransportParameters
	require.NoError(t, restored.UnmarshalFromSessionTicket(params.MarshalForSessionTicket(nil)))
	require.Nil(t, restored.LegacyMinAckDelay)
	require.False(t, restored.ParseLegacyAckFrequency)
}
