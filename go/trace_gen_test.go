package echauth_test

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"crypto/ed25519"
	"crypto/rand"

	"github.com/grittygrease/echauth"
)

// GenerateTraces produces the wire traces for comparison
func TestGenerateTraces(t *testing.T) {
	// 1. Setup Keys and Time
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	spki := echauth.EncodeEd25519SPKI(pubKey)
	// spkiHash := echauth.ComputeSPKIHash(spki)
	notAfter := uint64(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix())

	// Signature (dummy)
	sig := make([]byte, 64)

	// --- A. GO/RUST PR#2 (DRAFT) - AuthRetry (Split) ---
	// Structure: Method(1) | NotAfter(8) | Authenticator(2+N) | Alg(2) | Sig(2+N)
	// PR#2 Method RPK = 0x00

	draftRetry := &echauth.AuthRetry{
		Method:        echauth.MethodRPK,
		NotAfter:      notAfter,
		Authenticator: spki,
		Algorithm:     echauth.Ed25519SignatureScheme,
		Signature:     sig,
	}

	draftBytes := draftRetry.Encode()
	fmt.Printf("\n=== GO/RUST PR#2 (DRAFT) - AuthRetry ===\n%s\n", hex.EncodeToString(draftBytes))

	// --- B. NSS (LEGACY) SIMULATION ---
	// Structure: Method(1) | NotBefore(8) | NotAfter(8) | Alg(2) | SPKI(2+N) | Sig(2+N)
	// Legacy Method RPK = 0x01

	legacyBytes := make([]byte, 0, 200)
	legacyBytes = append(legacyBytes, 0x01)               // Method
	legacyBytes = append(legacyBytes, make([]byte, 8)...) // NotBefore (Zero)

	naBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(naBytes, notAfter)
	legacyBytes = append(legacyBytes, naBytes...) // NotAfter

	legacyBytes = append(legacyBytes, 0x08, 0x07) // Alg (Ed25519)

	legacyBytes = append(legacyBytes, byte(len(spki)>>8), byte(len(spki)))
	legacyBytes = append(legacyBytes, spki...) // SPKI

	legacyBytes = append(legacyBytes, byte(len(sig)>>8), byte(len(sig)))
	legacyBytes = append(legacyBytes, sig...) // Sig

	fmt.Printf("\n=== NSS (LEGACY) SIMULATION ===\n%s\n", hex.EncodeToString(legacyBytes))
}
