package echauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestEncodeEd25519SPKI(t *testing.T) {
	publicKey := make([]byte, 32)
	for i := range publicKey {
		publicKey[i] = byte(i + 1)
	}

	spki := EncodeEd25519SPKI(publicKey)
	if len(spki) != 44 {
		t.Errorf("expected 44 bytes, got %d", len(spki))
	}

	// Check prefix
	for i := 0; i < 12; i++ {
		if spki[i] != ed25519SPKIPrefix[i] {
			t.Errorf("prefix mismatch at byte %d", i)
		}
	}

	// Check key
	for i := 0; i < 32; i++ {
		if spki[12+i] != publicKey[i] {
			t.Errorf("key mismatch at byte %d", i)
		}
	}
}

func TestExtractEd25519PublicKey(t *testing.T) {
	publicKey := make([]byte, 32)
	for i := range publicKey {
		publicKey[i] = byte(i + 42)
	}

	spki := EncodeEd25519SPKI(publicKey)
	extracted, err := ExtractEd25519PublicKey(spki)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i := 0; i < 32; i++ {
		if extracted[i] != publicKey[i] {
			t.Errorf("extracted key mismatch at byte %d", i)
		}
	}
}

func TestExtractEd25519PublicKeyWrongLength(t *testing.T) {
	spki := make([]byte, 40)
	_, err := ExtractEd25519PublicKey(spki)
	if err == nil {
		t.Error("expected error for wrong length")
	}
}

func TestExtractEd25519PublicKeyWrongPrefix(t *testing.T) {
	spki := make([]byte, 44)
	spki[0] = 0x31 // Wrong prefix
	_, err := ExtractEd25519PublicKey(spki)
	if err == nil {
		t.Error("expected error for wrong prefix")
	}
}

func TestSignVerifyRPK(t *testing.T) {
	// Generate key
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	echConfigTBS := []byte("test ECH config data")
	notAfter := time.Now().Add(24 * time.Hour)

	// Sign
	sig := SignRPK(echConfigTBS, privateKey, notAfter)
	if sig == nil {
		t.Fatal("SignRPK returned nil")
	}

	// Compute SPKI hash for trusted_keys
	spkiHash := ComputeSPKIHash(sig.Authenticator)

	// Build Auth
	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash},
		Signature:   sig,
	}

	// Verify
	err = VerifyRPK(echConfigTBS, auth, time.Now())
	if err != nil {
		t.Errorf("verification failed: %v", err)
	}
}

func TestVerifyRPKExpired(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	echConfigTBS := []byte("test config")
	notAfter := time.Now().Add(-1 * time.Hour) // Already expired

	sig := SignRPK(echConfigTBS, privateKey, notAfter)
	spkiHash := ComputeSPKIHash(sig.Authenticator)

	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash},
		Signature:   sig,
	}

	err := VerifyRPK(echConfigTBS, auth, time.Now())
	if err == nil {
		t.Error("expected expiration error")
	}
}

func TestVerifyRPKWrongKey(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	echConfigTBS := []byte("test config")
	notAfter := time.Now().Add(24 * time.Hour)

	sig := SignRPK(echConfigTBS, privateKey, notAfter)

	// Use a different trusted key
	wrongHash := SPKIHash{}
	for i := range wrongHash {
		wrongHash[i] = 0x99
	}

	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{wrongHash},
		Signature:   sig,
	}

	err := VerifyRPK(echConfigTBS, auth, time.Now())
	if err == nil {
		t.Error("expected untrusted key error")
	}
}

func TestVerifyRPKWrongSignature(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	echConfigTBS := []byte("test config")
	notAfter := time.Now().Add(24 * time.Hour)

	sig := SignRPK(echConfigTBS, privateKey, notAfter)
	spkiHash := ComputeSPKIHash(sig.Authenticator)

	// Corrupt signature
	sig.SignatureData[0] ^= 1

	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash},
		Signature:   sig,
	}

	err := VerifyRPK(echConfigTBS, auth, time.Now())
	if err == nil {
		t.Error("expected signature invalid error")
	}
}

func TestVerifyRPKWrongConfig(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	echConfigTBS := []byte("test config")
	notAfter := time.Now().Add(24 * time.Hour)

	sig := SignRPK(echConfigTBS, privateKey, notAfter)
	spkiHash := ComputeSPKIHash(sig.Authenticator)

	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash},
		Signature:   sig,
	}

	// Verify with wrong config
	wrongConfig := []byte("different config")
	err := VerifyRPK(wrongConfig, auth, time.Now())
	if err == nil {
		t.Error("expected signature invalid error")
	}
}

func TestEncodeDecodeRoundtrip(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	echConfigTBS := []byte("test config for roundtrip")
	notAfter := time.Now().Add(24 * time.Hour)

	sig := SignRPK(echConfigTBS, privateKey, notAfter)
	spkiHash := ComputeSPKIHash(sig.Authenticator)

	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash, {1, 2, 3}}, // Multiple keys
		Signature:   sig,
	}

	// Encode
	encoded := auth.Encode()

	// Decode
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	// Check fields
	if decoded.Method != auth.Method {
		t.Errorf("method mismatch: %v != %v", decoded.Method, auth.Method)
	}

	if len(decoded.TrustedKeys) != len(auth.TrustedKeys) {
		t.Errorf("trusted_keys count mismatch: %d != %d", len(decoded.TrustedKeys), len(auth.TrustedKeys))
	}

	for i, key := range decoded.TrustedKeys {
		if key != auth.TrustedKeys[i] {
			t.Errorf("trusted_keys[%d] mismatch", i)
		}
	}

	if decoded.Signature == nil {
		t.Fatal("signature is nil")
	}

	if decoded.Signature.NotAfter != auth.Signature.NotAfter {
		t.Errorf("not_after mismatch")
	}

	if decoded.Signature.Algorithm != auth.Signature.Algorithm {
		t.Errorf("algorithm mismatch")
	}

	// Verify decoded auth still works
	err = VerifyRPK(echConfigTBS, decoded, time.Now())
	if err != nil {
		t.Errorf("verification of decoded auth failed: %v", err)
	}
}

func TestDecodeNoSignature(t *testing.T) {
	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{{1, 2, 3}},
		Signature:   nil,
	}

	encoded := auth.Encode()
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.Signature != nil {
		t.Error("expected nil signature")
	}
}

func TestMultipleTrustedKeys(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	echConfigTBS := []byte("test config")
	notAfter := time.Now().Add(24 * time.Hour)

	sig := SignRPK(echConfigTBS, privateKey, notAfter)
	spkiHash := ComputeSPKIHash(sig.Authenticator)

	// Put the correct key in the middle
	auth := &Auth{
		Method: MethodRPK,
		TrustedKeys: []SPKIHash{
			{1, 1, 1},
			{2, 2, 2},
			spkiHash,
			{3, 3, 3},
		},
		Signature: sig,
	}

	err := VerifyRPK(echConfigTBS, auth, time.Now())
	if err != nil {
		t.Errorf("verification failed with multiple keys: %v", err)
	}
}
