package quic

import (
	"crypto/tls"

	"github.com/enetx/quic-go/internal/handshake"
)

// SessionVersion returns the negotiated QUIC version recorded locally alongside
// a client session ticket. It does not validate ticket expiry or authenticity;
// the TLS engine retains all session validation. Unmarked/invalid states return
// false. The metadata uses SessionState.Extra and does not change ticket bytes.
func SessionVersion(session *tls.ClientSessionState) (Version, bool) {
	if session == nil {
		return 0, false
	}
	_, state, err := session.ResumptionState()
	if err != nil || state == nil {
		return 0, false
	}
	return handshake.SessionVersion(state.Extra)
}
