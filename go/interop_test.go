package echauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestVector represents a test vector from Rust implementation
type TestVector struct {
	Name              string `json:"name"`
	SigningKeyHex     string `json:"signing_key_hex"`
	ECHConfigTBSHex   string `json:"ech_config_tbs_hex"`
	NotAfter          uint64 `json:"not_after"`
	SPKIHex           string `json:"spki_hex"`
	SPKIHashHex       string `json:"spki_hash_hex"`
	SignatureHex      string `json:"signature_hex"`
	Algorithm         uint16 `json:"algorithm"`
	ECHAuthEncodedHex string `json:"ech_auth_encoded_hex"`
}

func TestInteropVerifyRustSignature(t *testing.T) {
	// Load test vector
	data, err := os.ReadFile("../interop-vector.json")
	if err != nil {
		t.Skipf("interop vector not found: %v", err)
	}

	var tv TestVector
	if err := json.Unmarshal(data, &tv); err != nil {
		t.Fatalf("failed to parse test vector: %v", err)
	}

	t.Logf("Testing vector: %s", tv.Name)

	// Decode hex values
	echConfigTBS, _ := hex.DecodeString(tv.ECHConfigTBSHex)
	spki, _ := hex.DecodeString(tv.SPKIHex)
	spkiHashExpected, _ := hex.DecodeString(tv.SPKIHashHex)
	signatureData, _ := hex.DecodeString(tv.SignatureHex)
	echAuthEncoded, _ := hex.DecodeString(tv.ECHAuthEncodedHex)

	// Verify SPKI hash computation matches
	spkiHash := ComputeSPKIHash(spki)
	if !bytes.Equal(spkiHash[:], spkiHashExpected) {
		t.Errorf("SPKI hash mismatch:\n  got:  %x\n  want: %x", spkiHash[:], spkiHashExpected)
	} else {
		t.Logf("SPKI hash matches: %x", spkiHash[:])
	}

	// Verify we can extract public key from SPKI
	publicKey, err := ExtractEd25519PublicKey(spki)
	if err != nil {
		t.Fatalf("failed to extract public key: %v", err)
	}
	t.Logf("Extracted public key: %x", publicKey)

	// Build Auth manually for verification
	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash},
		Signature: &Signature{
			Authenticator: spki,
			NotAfter:      tv.NotAfter,
			Algorithm:     tv.Algorithm,
			SignatureData: signatureData,
		},
	}

	// Verify signature using Go implementation
	verifyTime := time.Unix(1893455000, 0) // Before not_after
	err = VerifyRPK(echConfigTBS, auth, verifyTime)
	if err != nil {
		t.Errorf("Go failed to verify Rust signature: %v", err)
	} else {
		t.Log("SUCCESS: Go verified Rust-generated signature")
	}

	// Test decoding the wire format
	decoded, err := Decode(echAuthEncoded)
	if err != nil {
		t.Fatalf("failed to decode Rust-encoded ECHAuth: %v", err)
	}

	t.Logf("Decoded method: %v", decoded.Method)
	t.Logf("Decoded trusted_keys: %d", len(decoded.TrustedKeys))
	t.Logf("Decoded signature algorithm: 0x%04x", decoded.Signature.Algorithm)

	// Verify the decoded auth
	err = VerifyRPK(echConfigTBS, decoded, verifyTime)
	if err != nil {
		t.Errorf("Go failed to verify decoded Rust ECHAuth: %v", err)
	} else {
		t.Log("SUCCESS: Go verified decoded Rust ECHAuth")
	}
}

func TestInteropGoSignatureForRust(t *testing.T) {
	// Use the same deterministic key as Rust
	keyBytes, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	privateKey := ed25519.NewKeyFromSeed(keyBytes)

	echConfigTBS := []byte("test ECH config for interop")
	notAfter := time.Unix(1893456000, 0)

	// Sign with Go
	sig := SignRPK(echConfigTBS, privateKey, notAfter)

	// Verify SPKI matches Rust
	expectedSPKI, _ := hex.DecodeString("302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if !bytes.Equal(sig.Authenticator, expectedSPKI) {
		t.Errorf("SPKI mismatch with Rust:\n  got:  %x\n  want: %x", sig.Authenticator, expectedSPKI)
	} else {
		t.Log("SPKI matches Rust")
	}

	// Verify signature matches Rust (Ed25519 is deterministic)
	expectedSig, _ := hex.DecodeString("8ca4021885d35a609b8dcbbd33ee0d09590f77720b4c4c4d74984b67bcc20d7e01a9f72061da2711dcda84cf3073544b05960141a004de11335da2513375d009")
	if !bytes.Equal(sig.SignatureData, expectedSig) {
		t.Errorf("Signature mismatch with Rust:\n  got:  %x\n  want: %x", sig.SignatureData, expectedSig)
	} else {
		t.Log("Signature matches Rust (deterministic Ed25519)")
	}

	// Build and encode Auth
	spkiHash := ComputeSPKIHash(sig.Authenticator)
	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash},
		Signature:   sig,
	}

	encoded := auth.Encode()

	// Compare with Rust encoding
	expectedEncoded, _ := hex.DecodeString("01002006e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9002c302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a0000000070dbd880080700408ca4021885d35a609b8dcbbd33ee0d09590f77720b4c4c4d74984b67bcc20d7e01a9f72061da2711dcda84cf3073544b05960141a004de11335da2513375d009")
	if !bytes.Equal(encoded, expectedEncoded) {
		t.Errorf("Encoded ECHAuth mismatch with Rust:\n  got:  %x\n  want: %x", encoded, expectedEncoded)
	} else {
		t.Log("SUCCESS: Encoded ECHAuth matches Rust byte-for-byte")
	}

	// Output for Rust verification
	t.Logf("\n=== Go-generated test vector for Rust verification ===")
	t.Logf("ech_auth_encoded_hex: %x", encoded)
	t.Logf("signature_hex: %x", sig.SignatureData)
}

func TestInteropBidirectional(t *testing.T) {
	// Generate a new random key
	keyBytes, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	privateKey := ed25519.NewKeyFromSeed(keyBytes)

	echConfigTBS := []byte("bidirectional interop test config")
	notAfter := time.Unix(2000000000, 0)

	// Sign with Go
	sig := SignRPK(echConfigTBS, privateKey, notAfter)
	spkiHash := ComputeSPKIHash(sig.Authenticator)

	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash},
		Signature:   sig,
	}

	// Encode
	encoded := auth.Encode()

	// Decode
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	// Verify
	verifyTime := time.Unix(1999999999, 0)
	err = VerifyRPK(echConfigTBS, decoded, verifyTime)
	if err != nil {
		t.Errorf("verification failed: %v", err)
	}

	t.Logf("=== Bidirectional test vector ===")
	t.Logf("signing_key_hex: %x", keyBytes)
	t.Logf("ech_config_tbs_hex: %x", echConfigTBS)
	t.Logf("not_after: %d", notAfter.Unix())
	t.Logf("spki_hex: %x", sig.Authenticator)
	t.Logf("spki_hash_hex: %x", spkiHash)
	t.Logf("signature_hex: %x", sig.SignatureData)
	t.Logf("ech_auth_encoded_hex: %x", encoded)
}
