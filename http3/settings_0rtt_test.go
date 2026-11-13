package http3

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSettingsCompatibleFor0RTT(t *testing.T) {
	ticket := func(saved *settings) [][]byte {
		return [][]byte{settingsForSessionTicket(saved)}
	}

	for _, tc := range []struct {
		name       string
		current    *settings
		extra      [][]byte
		compatible bool
	}{
		{
			name:       "max field section size increased",
			current:    &settings{MaxFieldSectionSize: 101},
			extra:      ticket(&settings{MaxFieldSectionSize: 100}),
			compatible: true,
		},
		{
			name:    "missing settings",
			current: &settings{},
		},
		{
			name:    "malformed settings",
			current: &settings{},
			extra:   [][]byte{append([]byte(serverSettingsSessionTicketPrefix), 0xff)},
		},
		{
			name:    "max field section size reduced",
			current: &settings{MaxFieldSectionSize: 100},
			extra:   ticket(&settings{MaxFieldSectionSize: 101}),
		},
		{
			name:    "datagrams disabled",
			current: &settings{MaxFieldSectionSize: 100},
			extra: ticket(&settings{
				MaxFieldSectionSize: 100,
				Datagram:            true,
			}),
		},
		{
			name:    "unknown setting",
			current: &settings{MaxFieldSectionSize: 100},
			extra: ticket(&settings{
				MaxFieldSectionSize: 100,
				Other:               orderedTestSettings(map[uint64]uint64{13: 37}),
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, ok := settingsDataFromSessionTicket(tc.extra)
			require.Equal(t, tc.compatible, ok && settingsCompatibleFor0RTT(data, tc.current))
		})
	}
}

func TestServerQPACKSettingsForEarlyData(t *testing.T) {
	for _, tc := range []struct {
		name                                       string
		oldCapacity, capacity, oldBlocked, blocked uint64
		allowed                                    bool
	}{
		{"same", 4096, 4096, 16, 16, true},
		{"new table", 0, 4096, 0, 16, true},
		{"more blocked", 4096, 4096, 16, 32, true},
		{"less blocked", 4096, 4096, 16, 1, false},
		{"larger table", 4096, 8192, 16, 16, false},
		{"smaller table", 4096, 1024, 16, 16, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := &settings{MaxFieldSectionSize: 4096, Other: orderedTestSettings(map[uint64]uint64{1: tc.oldCapacity, 7: tc.oldBlocked, 64: 123})}
			current := &settings{MaxFieldSectionSize: 4096, Other: orderedTestSettings(map[uint64]uint64{1: tc.capacity, 7: tc.blocked, 95: 456})}
			data, ok := settingsDataFromSessionTicket([][]byte{settingsForSessionTicket(old)})
			require.True(t, ok)
			require.Equal(t, tc.allowed, settingsCompatibleFor0RTT(data, current))
		})
	}
}
