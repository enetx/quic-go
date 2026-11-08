package http3

import (
	"sort"

	"github.com/enetx/g"
)

// orderedTestSettings adapts upstream map fixtures without randomizing wire order.
func orderedTestSettings(m map[uint64]uint64) g.MapOrd[uint64, uint64] {
	if m == nil {
		return nil
	}
	keys := make([]uint64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	result := g.NewMapOrd[uint64, uint64]()
	for _, k := range keys {
		result.Insert(k, m[k])
	}
	return result
}
