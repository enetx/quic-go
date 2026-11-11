package handshake

import (
	"bytes"
	"encoding/binary"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/quicvarint"
)

// SessionVersion reads only QUIC's own local metadata, leaving TLS's opaque
// session encoding and all ticket validation to the TLS engine.
func SessionVersion(extras [][]byte) (protocol.Version, bool) {
	var version protocol.Version
	found := false
	for _, extra := range extras {
		data, ok := bytes.CutPrefix(extra, []byte(extraPrefix))
		if !ok {
			continue
		}
		revision, width, err := quicvarint.Parse(data)
		if err != nil || revision != clientSessionStateRevision || len(data)-width < 4 || found {
			return 0, false
		}
		data = data[width:]
		version = protocol.Version(binary.BigEndian.Uint32(data))
		if version != protocol.Version1 && version != protocol.Version2 {
			return 0, false
		}
		found = true
	}
	return version, found
}
