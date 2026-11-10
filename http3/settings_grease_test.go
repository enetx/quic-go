package http3

import (
	"errors"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestConnectionSettingsGreaseValidatesBeforeMutation(t *testing.T) {
	settings := g.NewMapOrd[uint64, uint64]()
	settings.Insert(1, 65536)
	for _, pair := range [][2]uint64{{0, 0}, {1, 1}, {34, 1}, {quicvarint.Max + 1, 1}, {64, quicvarint.Max + 1}} {
		_, err := connectionSettingsGrease(settings, func() (uint64, uint64, error) { return pair[0], pair[1], nil })
		require.Error(t, err)
		require.Equal(t, 1, settings.Len().Std())
	}
	snapshot, err := connectionSettingsGrease(settings, func() (uint64, uint64, error) { return 64, quicvarint.Max, nil })
	require.NoError(t, err)
	require.False(t, settings.Contains(64))
	require.EqualValues(t, quicvarint.Max, snapshot.Get(64).Unwrap())
	snapshot.Insert(1, 0)
	require.EqualValues(t, 65536, settings.Get(1).Unwrap())
	_, err = connectionSettingsGrease(snapshot, func() (uint64, uint64, error) { return 64, 2, nil })
	require.ErrorContains(t, err, "duplicate")
	failure := errors.New("factory failure")
	_, err = connectionSettingsGrease(settings, func() (uint64, uint64, error) { return 64, 2, failure })
	require.ErrorIs(t, err, failure)
	empty, err := connectionSettingsGrease(nil, func() (uint64, uint64, error) { return 33, 0, nil })
	require.NoError(t, err)
	require.True(t, empty.Contains(33))
}
