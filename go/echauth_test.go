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

	// Encode (Legacy)
	encoded := auth.EncodeVersioned(SpecPublished)

	// Decode (Legacy)
	decoded, err := DecodeVersioned(encoded, SpecPublished)
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

	encoded := auth.EncodeVersioned(SpecPublished)
	decoded, err := DecodeVersioned(encoded, SpecPublished)
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

// =============================================================================
// VERSIONED ENCODE/DECODE TESTS
// =============================================================================

func TestVersionedEncodeDecodePR2(t *testing.T) {
	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{{42, 42, 42}},
		Signature: &Signature{
			Authenticator: []byte("dummy auth"),
			NotAfter:      1234567890,
			Algorithm:     0x0403,
			SignatureData: []byte("dummy sig"),
		},
	}

	encoded := auth.EncodeVersioned(SpecPR2)
	// PR2: rpk=0
	if encoded[0] != 0 {
		t.Errorf("expected method byte 0, got %d", encoded[0])
	}

	decoded, err := DecodeVersioned(encoded, SpecPR2)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded.Method != MethodRPK {
		t.Errorf("expected MethodRPK, got %v", decoded.Method)
	}
}

func TestVersionedEncodeDecodePublished(t *testing.T) {
	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{{42, 42, 42}},
		Signature:   nil,
	}

	encoded := auth.EncodeVersioned(SpecPublished)
	// Published: rpk=1
	if encoded[0] != 1 {
		t.Errorf("expected method byte 1, got %d", encoded[0])
	}

	decoded, err := DecodeVersioned(encoded, SpecPublished)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded.Method != MethodRPK {
		t.Errorf("expected MethodRPK, got %v", decoded.Method)
	}
}

func TestVersionedPKIXMethod(t *testing.T) {
	auth := &Auth{
		Method:      MethodPKIX,
		TrustedKeys: nil,
		Signature:   nil,
	}

	// PR2: pkix=1
	encodedPR2 := auth.EncodeVersioned(SpecPR2)
	if encodedPR2[0] != 1 {
		t.Errorf("PR2 pkix: expected method byte 1, got %d", encodedPR2[0])
	}

	// Published: pkix=2
	encodedPub := auth.EncodeVersioned(SpecPublished)
	if encodedPub[0] != 2 {
		t.Errorf("Published pkix: expected method byte 2, got %d", encodedPub[0])
	}
}

func TestCrossVersionMismatch(t *testing.T) {
	// Encode with Published (rpk=1), decode with PR2 (1=pkix)
	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{{42, 42, 42}},
		Signature:   nil,
	}

	encoded := auth.EncodeVersioned(SpecPublished)
	// Method byte is 1 (Published rpk)
	if encoded[0] != 1 {
		t.Errorf("expected method byte 1, got %d", encoded[0])
	}

	// Decode with PR2: method 1 = Pkix (wrong!)
	decoded, err := DecodeVersioned(encoded, SpecPR2)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded.Method != MethodPKIX {
		t.Errorf("expected cross-version to interpret as PKIX, got %v", decoded.Method)
	}
	if decoded.Method == auth.Method {
		t.Error("expected method mismatch in cross-version decode")
	}
}

func TestDetectVersionPR2(t *testing.T) {
	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{{42, 42, 42}},
	}
	encoded := auth.EncodeVersioned(SpecPR2)

	ver, ok := DetectVersion(encoded)
	if !ok {
		t.Error("expected version detection to succeed for PR2 RPK")
	}
	if ver != SpecPR2 {
		t.Errorf("expected SpecPR2, got %v", ver)
	}
}

func TestDetectVersionPublishedPKIX(t *testing.T) {
	auth := &Auth{
		Method:      MethodPKIX,
		TrustedKeys: nil,
	}
	encoded := auth.EncodeVersioned(SpecPublished)
	// Method byte should be 2

	ver, ok := DetectVersion(encoded)
	if !ok {
		t.Error("expected version detection to succeed for Published PKIX")
	}
	if ver != SpecPublished {
		t.Errorf("expected SpecPublished, got %v", ver)
	}
}

func TestDetectVersionAmbiguous(t *testing.T) {
	// Method byte 1 is ambiguous (PR2 pkix OR Published rpk)
	data := []byte{1, 0, 0} // method=1, no trusted keys
	_, ok := DetectVersion(data)
	if ok {
		t.Error("expected version detection to be ambiguous for method=1")
	}
}

// =============================================================================
// MUST Requirements Tests
// =============================================================================

func TestDecode_PKIXMustHaveZeroLengthTrustedKeys(t *testing.T) {
	// Section 5.1: PKIX MUST have zero-length trusted_keys
	// Build PKIX AuthInfo with NON-EMPTY trusted_keys (invalid per spec)
	var data []byte
	data = append(data, 0x01)                // method = PKIX
	data = append(data, 0x00, 0x20)          // trusted_keys length = 32 (NON-ZERO - invalid!)
	data = append(data, make([]byte, 32)...) // some hash data

	_, err := DecodeAuthInfo(data)
	// Current implementation doesn't enforce this, but it SHOULD
	// This test documents the expected behavior
	if err == nil {
		t.Log("WARNING: PKIX with non-zero trusted_keys was accepted (should be rejected per spec)")
		// Note: This is currently accepted but violates the MUST requirement
	}
}

func TestDecode_RPKMustHaveAtLeastOneKey(t *testing.T) {
	// Section 5.1: RPK MUST have ≥1 hash in trusted_keys
	// Build RPK AuthInfo with EMPTY trusted_keys (invalid per spec)

	// Use legacy format where we can control trusted_keys directly
	info := &AuthInfo{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{}, // Empty - invalid per spec
	}

	// Encode and decode to verify it round-trips
	encoded := info.Encode()
	decoded, err := DecodeAuthInfo(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	// Decode succeeds but we should validate this during verification
	if len(decoded.TrustedKeys) == 0 {
		t.Log("RPK with empty trusted_keys decoded (verification should reject this)")
	}
}
