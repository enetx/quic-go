package http3_test

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestHTTP3SettingsGreaseFactoryPerConnection(t *testing.T) {
	var calls atomic.Uint64
	config := &http3.WireConfig{CoalesceInitialSettings: true, SettingsGrease: func() (uint64, uint64, error) { return 64, calls.Add(1), nil }}
	for expected := uint64(1); expected <= 3; expected++ {
		p := newQPACKStartupPair(t, nil, nil, config)
		control, err := p.server.AcceptUniStream(p.ctx)
		require.NoError(t, err)
		typ, err := quicvarint.Read(quicvarint.NewReader(control))
		require.NoError(t, err)
		require.Zero(t, typ)
		frame, data := readWireFrame(t, control)
		require.EqualValues(t, 4, frame)
		values := map[uint64]uint64{}
		for len(data) > 0 {
			id, n, err := quicvarint.Parse(data)
			require.NoError(t, err)
			data = data[n:]
			v, n, err := quicvarint.Parse(data)
			require.NoError(t, err)
			data = data[n:]
			values[id] = v
		}
		require.Equal(t, expected, values[64])
		require.EqualValues(t, 256, values[1])
		require.EqualValues(t, 4, values[7])
		p.sendHeaders(t)
		p.sendHeaders(t)
		require.Equal(t, expected, calls.Load(), "requests regenerated connection settings")
	}
}
func TestHTTP3SettingsGreaseFactoryFailsBeforeStreams(t *testing.T) {
	failure := errors.New("settings factory failed")
	for _, factory := range []func() (uint64, uint64, error){
		func() (uint64, uint64, error) { return 64, 0, failure }, func() (uint64, uint64, error) { return 1, 1, nil },
	} {
		p := newQPACKStartupPair(t, nil, nil, &http3.WireConfig{CoalesceInitialSettings: true, SettingsGrease: factory})
		_, err := p.h3.OpenRequestStream(p.ctx)
		require.Error(t, err)
		var prep *http3.RequestPreparationError
		require.ErrorAs(t, err, &prep)
	}
}
