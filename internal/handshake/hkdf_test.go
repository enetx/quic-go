package handshake

import (
	"crypto"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

var tls13CipherSuites = []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256}

func suiteHash(id uint16) crypto.Hash {
	if id == tls.TLS_AES_256_GCM_SHA384 {
		return crypto.SHA384
	}
	return crypto.SHA256
}

// Fixed RFC 8446 Expand-Label vectors replace a comparison through private
// crypto/tls symbols. Go 1.27 no longer permits those linkname references.
func TestHKDF(t *testing.T) {
	for _, id := range tls13CipherSuites {
		t.Run(tls.CipherSuiteName(id), func(t *testing.T) {
			hash := suiteHash(id)
			vectors := map[crypto.Hash]string{
				crypto.SHA256: "9587032ee5e616675a05dca9bd0a1e42986c0f0db06ea7d29e3154c9d3ba8970",
				crypto.SHA384: "9bec9efa1fa6c8f06b0d884372852d70120c5740cdadb1e2816f75a9dc27a9b7d5e36c4e419e43394db475e0ead73c28",
			}
			expected, err := hex.DecodeString(vectors[hash])
			require.NoError(t, err)
			require.Equal(t, expected, hkdfExpandLabel(hash, []byte("foobar"), nil, "traffic upd", hash.Size()))
		})
	}
}
func BenchmarkHKDFExpandLabelStandardLibrary(b *testing.B) {
	for _, id := range tls13CipherSuites {
		b.Run(tls.CipherSuiteName(id), func(b *testing.B) { benchmarkHKDFExpandLabel(b, id, true) })
	}
}
func BenchmarkHKDFExpandLabelOurs(b *testing.B) {
	for _, id := range tls13CipherSuites {
		b.Run(tls.CipherSuiteName(id), func(b *testing.B) { benchmarkHKDFExpandLabel(b, id, false) })
	}
}
func benchmarkHKDFExpandLabel(b *testing.B, id uint16, standard bool) {
	b.ReportAllocs()
	hash := suiteHash(id)
	secret := make([]byte, hash.Size())
	rand.Read(secret)
	info := append([]byte{0, byte(hash.Size()), 17}, []byte("tls13 traffic upd")...)
	info = append(info, 0)
	for b.Loop() {
		if standard {
			_, err := hkdf.Expand(hash.New, secret, string(info), hash.Size())
			if err != nil {
				b.Fatal(err)
			}
		} else {
			hkdfExpandLabel(hash, secret, nil, "traffic upd", hash.Size())
		}
	}
}
