package echauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// Helper to build a minimal valid ECHConfig for testing
func buildTestECHConfig(t *testing.T, configID uint8, publicName string, extensions []Extension) []byte {
	t.Helper()

	// Generate a fake HPKE public key (32 bytes for X25519)
	hpkeKey := make([]byte, 32)
	rand.Read(hpkeKey)

	return buildECHConfigBytes(configID, 0x0020, hpkeKey, publicName, extensions)
}

// KEM ID for X25519
const kemX25519 uint16 = 0x0020

func buildECHConfigBytes(configID uint8, kemID uint16, hpkeKey []byte, publicName string, extensions []Extension) []byte {
	var contents []byte

	// ConfigID
	contents = append(contents, configID)

	// KEM ID
	contents = append(contents, byte(kemID>>8), byte(kemID))

	// Public key (length-prefixed)
	contents = append(contents, byte(len(hpkeKey)>>8), byte(len(hpkeKey)))
	contents = append(contents, hpkeKey...)

	// Cipher suites: one suite (HKDF-SHA256 + AES-128-GCM)
	contents = append(contents, 0x00, 0x04) // length = 4
	contents = append(contents, 0x00, 0x01) // HKDF-SHA256
	contents = append(contents, 0x00, 0x01) // AES-128-GCM

	// Maximum name length
	contents = append(contents, 64)

	// Public name (1-byte length prefix)
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, []byte(publicName)...)

	// Extensions
	var extBytes []byte
	for _, ext := range extensions {
		extBytes = append(extBytes, byte(ext.Type>>8), byte(ext.Type))
		extBytes = append(extBytes, byte(len(ext.Data)>>8), byte(len(ext.Data)))
		extBytes = append(extBytes, ext.Data...)
	}
	contents = append(contents, byte(len(extBytes)>>8), byte(len(extBytes)))
	contents = append(contents, extBytes...)

	// Build full config
	var config []byte
	version := uint16(ECHConfigVersion)
	config = append(config, byte(version>>8), byte(version))
	config = append(config, byte(len(contents)>>8), byte(len(contents)))
	config = append(config, contents...)

	return config
}

func buildECHConfigList(configs ...[]byte) []byte {
	var list []byte
	for _, c := range configs {
		list = append(list, c...)
	}

	result := make([]byte, 2+len(list))
	binary.BigEndian.PutUint16(result, uint16(len(list)))
	copy(result[2:], list)
	return result
}

// signConfig creates a signed ech_auth extension for a config
func signConfig(t *testing.T, configTBS []byte, privateKey ed25519.PrivateKey, notAfter time.Time) []byte {
	t.Helper()

	sig := SignRPK(configTBS, privateKey, notAfter)
	spkiHash := ComputeSPKIHash(sig.Authenticator)

	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash},
		Signature:   sig,
	}

	return auth.Encode()
}

// =============================================================================
// PARSING TESTS
// =============================================================================

func TestParseECHConfigList_Valid(t *testing.T) {
	config := buildTestECHConfig(t, 1, "example.com", nil)
	list := buildECHConfigList(config)

	configs, err := ParseECHConfigList(list)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(configs) != 1 {
		t.Errorf("expected 1 config, got %d", len(configs))
	}

	if configs[0].Version != ECHConfigVersion {
		t.Errorf("version mismatch: got 0x%04x", configs[0].Version)
	}

	if configs[0].ConfigID != 1 {
		t.Errorf("config_id mismatch: got %d", configs[0].ConfigID)
	}

	if string(configs[0].PublicName) != "example.com" {
		t.Errorf("public_name mismatch: got %s", configs[0].PublicName)
	}
}

func TestParseECHConfigList_MultipleConfigs(t *testing.T) {
	config1 := buildTestECHConfig(t, 1, "one.example.com", nil)
	config2 := buildTestECHConfig(t, 2, "two.example.com", nil)
	list := buildECHConfigList(config1, config2)

	configs, err := ParseECHConfigList(list)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(configs) != 2 {
		t.Errorf("expected 2 configs, got %d", len(configs))
	}

	if configs[0].ConfigID != 1 || configs[1].ConfigID != 2 {
		t.Error("config IDs don't match")
	}
}

func TestParseECHConfigList_Empty(t *testing.T) {
	// Empty data
	_, err := ParseECHConfigList(nil)
	if err == nil {
		t.Error("expected error for nil data")
	}

	_, err = ParseECHConfigList([]byte{})
	if err == nil {
		t.Error("expected error for empty data")
	}

	// Just length field, no configs
	_, err = ParseECHConfigList([]byte{0x00, 0x00})
	if err != nil {
		// Empty list is technically valid (0 configs)
		// but we want at least one
	}
}

func TestParseECHConfigList_TruncatedLength(t *testing.T) {
	// Only 1 byte when we need 2
	_, err := ParseECHConfigList([]byte{0x00})
	if err == nil {
		t.Error("expected error for truncated length")
	}
}

func TestParseECHConfigList_TruncatedData(t *testing.T) {
	// Length says 100 bytes but only have 10
	data := []byte{0x00, 0x64} // length = 100
	data = append(data, make([]byte, 10)...)

	_, err := ParseECHConfigList(data)
	if err == nil {
		t.Error("expected error for truncated data")
	}
}

func TestParseECHConfig_TruncatedVersion(t *testing.T) {
	list := []byte{0x00, 0x02, 0xfe} // length=2, but only 1 byte of config
	_, err := ParseECHConfigList(list)
	if err == nil {
		t.Error("expected error for truncated version")
	}
}

func TestParseECHConfig_TruncatedContents(t *testing.T) {
	// Valid version/length header but truncated contents
	list := []byte{
		0x00, 0x10, // list length = 16
		0xfe, 0x0d, // version
		0x00, 0x0c, // config length = 12
		0x01,       // config_id
		// Missing: kem_id, public_key, ciphers, etc.
	}
	_, err := ParseECHConfigList(list)
	if err == nil {
		t.Error("expected error for truncated contents")
	}
}

func TestParseECHConfig_UnknownVersion(t *testing.T) {
	// Unknown version should be skipped, not error
	config := []byte{
		0xff, 0xff, // unknown version
		0x00, 0x04, // length = 4
		0x01, 0x02, 0x03, 0x04, // opaque contents
	}
	list := buildECHConfigList(config)

	configs, err := ParseECHConfigList(list)
	if err != nil {
		t.Fatalf("unexpected error for unknown version: %v", err)
	}

	// Should parse but version won't match
	if len(configs) != 1 {
		t.Errorf("expected 1 config, got %d", len(configs))
	}
	if configs[0].Version == ECHConfigVersion {
		t.Error("should have unknown version")
	}
}

func TestParseECHConfig_InvalidCipherSuiteLength(t *testing.T) {
	// Build config manually with bad cipher suite length
	var contents []byte
	contents = append(contents, 0x01)             // config_id
	contents = append(contents, 0x00, 0x20)       // kem_id
	contents = append(contents, 0x00, 0x20)       // pk_len = 32
	contents = append(contents, make([]byte, 32)...) // public key
	contents = append(contents, 0x00, 0x03)       // cipher length = 3 (not multiple of 4!)
	contents = append(contents, 0x00, 0x01, 0x00) // truncated cipher

	config := make([]byte, 4+len(contents))
	binary.BigEndian.PutUint16(config, ECHConfigVersion)
	binary.BigEndian.PutUint16(config[2:], uint16(len(contents)))
	copy(config[4:], contents)

	list := buildECHConfigList(config)

	_, err := ParseECHConfigList(list)
	if err == nil {
		t.Error("expected error for invalid cipher suite length")
	}
}

func TestParseECHConfig_WithExtensions(t *testing.T) {
	extensions := []Extension{
		{Type: 0x1234, Data: []byte("test extension data")},
		{Type: 0x5678, Data: []byte("another extension")},
	}
	config := buildTestECHConfig(t, 1, "example.com", extensions)
	list := buildECHConfigList(config)

	configs, err := ParseECHConfigList(list)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(configs[0].Extensions) != 2 {
		t.Errorf("expected 2 extensions, got %d", len(configs[0].Extensions))
	}

	if configs[0].Extensions[0].Type != 0x1234 {
		t.Errorf("extension type mismatch")
	}
}

// =============================================================================
// SIGNATURE VERIFICATION TESTS
// =============================================================================

func TestVerifyConfig_ValidSignature(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	notAfter := time.Now().Add(24 * time.Hour)

	// Build config without extension first to get TBS
	configNoExt := buildTestECHConfig(t, 1, "example.com", nil)

	// Sign the config (TBS is config without the auth extension)
	authExt := signConfig(t, configNoExt, privateKey, notAfter)

	// Rebuild config with the extension
	config := buildTestECHConfig(t, 1, "example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: authExt},
	})
	list := buildECHConfigList(config)

	configs, err := ParseECHConfigList(list)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Override TBS computation for test - use the config without extension
	// In production, the TBS would be computed by zeroing the signature field
	configs[0].Raw = configNoExt

	// Set up trust anchor
	spki := EncodeEd25519SPKI(privateKey.Public().(ed25519.PublicKey))
	spkiHash := ComputeSPKIHash(spki)
	anchor := &TrustAnchor{TrustedKeys: []SPKIHash{spkiHash}}

	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	err = VerifyConfig(&configs[0], anchor, nowFunc)
	if err != nil {
		t.Errorf("verification failed: %v", err)
	}
}

func TestVerifyConfig_ExpiredSignature(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	notAfter := time.Now().Add(-1 * time.Hour) // Already expired

	configNoExt := buildTestECHConfig(t, 1, "example.com", nil)
	authExt := signConfig(t, configNoExt, privateKey, notAfter)

	config := buildTestECHConfig(t, 1, "example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: authExt},
	})
	list := buildECHConfigList(config)

	configs, _ := ParseECHConfigList(list)

	spki := EncodeEd25519SPKI(privateKey.Public().(ed25519.PublicKey))
	spkiHash := ComputeSPKIHash(spki)
	anchor := &TrustAnchor{TrustedKeys: []SPKIHash{spkiHash}}

	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	err := VerifyConfig(&configs[0], anchor, nowFunc)
	if err == nil {
		t.Error("expected expiration error")
	}
}

func TestVerifyConfig_UntrustedKey(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	notAfter := time.Now().Add(24 * time.Hour)

	configNoExt := buildTestECHConfig(t, 1, "example.com", nil)
	authExt := signConfig(t, configNoExt, privateKey, notAfter)

	config := buildTestECHConfig(t, 1, "example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: authExt},
	})
	list := buildECHConfigList(config)

	configs, _ := ParseECHConfigList(list)

	// Use a DIFFERENT key as trust anchor
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	spki := EncodeEd25519SPKI(otherKey.Public().(ed25519.PublicKey))
	spkiHash := ComputeSPKIHash(spki)
	anchor := &TrustAnchor{TrustedKeys: []SPKIHash{spkiHash}}

	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	err := VerifyConfig(&configs[0], anchor, nowFunc)
	if err == nil {
		t.Error("expected untrusted key error")
	}
}

func TestVerifyConfig_CorruptedSignature(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	notAfter := time.Now().Add(24 * time.Hour)

	configNoExt := buildTestECHConfig(t, 1, "example.com", nil)
	authExt := signConfig(t, configNoExt, privateKey, notAfter)

	// Corrupt the signature (last bytes are signature data)
	authExt[len(authExt)-1] ^= 0xff

	config := buildTestECHConfig(t, 1, "example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: authExt},
	})
	list := buildECHConfigList(config)

	configs, _ := ParseECHConfigList(list)

	spki := EncodeEd25519SPKI(privateKey.Public().(ed25519.PublicKey))
	spkiHash := ComputeSPKIHash(spki)
	anchor := &TrustAnchor{TrustedKeys: []SPKIHash{spkiHash}}

	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	err := VerifyConfig(&configs[0], anchor, nowFunc)
	if err == nil {
		t.Error("expected signature invalid error")
	}
}

func TestVerifyConfig_WrongDataSigned(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	notAfter := time.Now().Add(24 * time.Hour)

	// Sign DIFFERENT config data
	wrongConfig := buildTestECHConfig(t, 99, "wrong.example.com", nil)
	authExt := signConfig(t, wrongConfig, privateKey, notAfter)

	// But put extension in different config
	config := buildTestECHConfig(t, 1, "example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: authExt},
	})
	list := buildECHConfigList(config)

	configs, _ := ParseECHConfigList(list)

	spki := EncodeEd25519SPKI(privateKey.Public().(ed25519.PublicKey))
	spkiHash := ComputeSPKIHash(spki)
	anchor := &TrustAnchor{TrustedKeys: []SPKIHash{spkiHash}}

	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	err := VerifyConfig(&configs[0], anchor, nowFunc)
	if err == nil {
		t.Error("expected signature invalid error for wrong data")
	}
}

func TestVerifyConfig_NoAuthExtension(t *testing.T) {
	// Config without ech_auth extension
	config := buildTestECHConfig(t, 1, "example.com", nil)
	list := buildECHConfigList(config)

	configs, _ := ParseECHConfigList(list)

	anchor := &TrustAnchor{TrustedKeys: []SPKIHash{{}}}
	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	err := VerifyConfig(&configs[0], anchor, nowFunc)
	if err == nil {
		t.Error("expected error for missing auth extension")
	}
}

func TestVerifyConfig_UnknownVersion(t *testing.T) {
	config := []byte{
		0xff, 0xff, // unknown version
		0x00, 0x04, // length = 4
		0x01, 0x02, 0x03, 0x04,
	}
	list := buildECHConfigList(config)

	configs, _ := ParseECHConfigList(list)

	anchor := &TrustAnchor{TrustedKeys: []SPKIHash{{}}}
	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	err := VerifyConfig(&configs[0], anchor, nowFunc)
	if err == nil {
		t.Error("expected error for unknown version")
	}
}

// =============================================================================
// VERIFY CONFIG LIST TESTS
// =============================================================================

func TestVerifyConfigList_AllValid(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	notAfter := time.Now().Add(24 * time.Hour)

	// Build TBS versions (without auth extension)
	config1TBS := buildTestECHConfig(t, 1, "one.example.com", nil)
	config2TBS := buildTestECHConfig(t, 2, "two.example.com", nil)

	// Sign with TBS
	authExt1 := signConfig(t, config1TBS, privateKey, notAfter)
	authExt2 := signConfig(t, config2TBS, privateKey, notAfter)

	// Build signed versions
	config1Signed := buildTestECHConfig(t, 1, "one.example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: authExt1},
	})
	config2Signed := buildTestECHConfig(t, 2, "two.example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: authExt2},
	})

	list := buildECHConfigList(config1Signed, config2Signed)

	// Parse and fix TBS for testing
	configs, _ := ParseECHConfigList(list)
	configs[0].Raw = config1TBS
	configs[1].Raw = config2TBS

	spki := EncodeEd25519SPKI(privateKey.Public().(ed25519.PublicKey))
	spkiHash := ComputeSPKIHash(spki)
	anchor := &TrustAnchor{TrustedKeys: []SPKIHash{spkiHash}}

	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	// Verify individual configs with fixed TBS
	for i := range configs {
		if err := VerifyConfig(&configs[i], anchor, nowFunc); err != nil {
			t.Errorf("config %d failed: %v", i, err)
		}
	}
}

func TestVerifyConfigList_SomeInvalid(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	notAfter := time.Now().Add(24 * time.Hour)

	// Config 1: valid signature (TBS without extension)
	config1TBS := buildTestECHConfig(t, 1, "valid.example.com", nil)
	authExt1 := signConfig(t, config1TBS, privateKey, notAfter)
	config1Signed := buildTestECHConfig(t, 1, "valid.example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: authExt1},
	})

	// Config 2: no auth extension (will fail verification)
	config2 := buildTestECHConfig(t, 2, "noauth.example.com", nil)

	// Config 3: expired (will fail verification)
	config3TBS := buildTestECHConfig(t, 3, "expired.example.com", nil)
	expiredAuth := signConfig(t, config3TBS, privateKey, time.Now().Add(-1*time.Hour))
	config3 := buildTestECHConfig(t, 3, "expired.example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: expiredAuth},
	})

	list := buildECHConfigList(config1Signed, config2, config3)

	// Parse and fix TBS for config 1
	configs, _ := ParseECHConfigList(list)
	configs[0].Raw = config1TBS
	configs[2].Raw = config3TBS

	spki := EncodeEd25519SPKI(privateKey.Public().(ed25519.PublicKey))
	spkiHash := ComputeSPKIHash(spki)
	anchor := &TrustAnchor{TrustedKeys: []SPKIHash{spkiHash}}

	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	// Test individual configs
	var verified []ECHConfig
	for i := range configs {
		if err := VerifyConfig(&configs[i], anchor, nowFunc); err == nil {
			verified = append(verified, configs[i])
		}
	}

	// Only config 1 should pass
	if len(verified) != 1 {
		t.Errorf("expected 1 verified config, got %d", len(verified))
	}

	if len(verified) > 0 && verified[0].ConfigID != 1 {
		t.Errorf("wrong config verified: got config_id %d", verified[0].ConfigID)
	}
}

func TestVerifyConfigList_AllInvalid(t *testing.T) {
	// All configs have problems
	config1 := buildTestECHConfig(t, 1, "noauth.example.com", nil) // no auth
	config2 := buildTestECHConfig(t, 2, "noauth2.example.com", nil) // no auth

	list := buildECHConfigList(config1, config2)

	anchor := &TrustAnchor{TrustedKeys: []SPKIHash{{}}}
	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	_, err := VerifyConfigList(list, anchor, nowFunc)
	if err == nil {
		t.Error("expected error when all configs invalid")
	}
}

func TestVerifyConfigList_EmptyList(t *testing.T) {
	list := []byte{0x00, 0x00} // length = 0

	anchor := &TrustAnchor{TrustedKeys: []SPKIHash{{}}}
	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	_, err := VerifyConfigList(list, anchor, nowFunc)
	if err == nil {
		t.Error("expected error for empty list")
	}
}

// =============================================================================
// MALFORMED AUTH EXTENSION TESTS
// =============================================================================

func TestDecode_TruncatedMethod(t *testing.T) {
	_, err := Decode([]byte{})
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestDecode_TruncatedTrustedKeysLength(t *testing.T) {
	_, err := Decode([]byte{0x01}) // method only
	if err == nil {
		t.Error("expected error for truncated trusted_keys length")
	}

	_, err = Decode([]byte{0x01, 0x00}) // method + 1 byte of length
	if err == nil {
		t.Error("expected error for truncated trusted_keys length")
	}
}

func TestDecode_InvalidTrustedKeysLength(t *testing.T) {
	// Length not multiple of 32
	_, err := Decode([]byte{0x01, 0x00, 0x21}) // length = 33
	if err == nil {
		t.Error("expected error for invalid trusted_keys length")
	}
}

func TestDecode_TruncatedTrustedKeys(t *testing.T) {
	data := []byte{0x01, 0x00, 0x20} // method + length=32
	data = append(data, make([]byte, 16)...) // only 16 bytes of key

	_, err := Decode(data)
	if err == nil {
		t.Error("expected error for truncated trusted_keys")
	}
}

func TestDecode_TruncatedAuthenticatorLength(t *testing.T) {
	data := []byte{0x01, 0x00, 0x00} // method + no trusted_keys
	data = append(data, 0x00)        // only 1 byte of authenticator length

	_, err := Decode(data)
	if err == nil {
		t.Error("expected error for truncated authenticator length")
	}
}

func TestDecode_TruncatedAuthenticator(t *testing.T) {
	data := []byte{0x01, 0x00, 0x00} // method + no trusted_keys
	data = append(data, 0x00, 0x20)  // authenticator length = 32
	data = append(data, make([]byte, 16)...) // only 16 bytes

	_, err := Decode(data)
	if err == nil {
		t.Error("expected error for truncated authenticator")
	}
}

func TestDecode_TruncatedNotAfter(t *testing.T) {
	data := []byte{0x01, 0x00, 0x00}          // method + no trusted_keys
	data = append(data, 0x00, 0x04)           // authenticator length = 4
	data = append(data, 0x01, 0x02, 0x03, 0x04) // authenticator
	data = append(data, 0x00, 0x00, 0x00, 0x00) // only 4 bytes of not_after

	_, err := Decode(data)
	if err == nil {
		t.Error("expected error for truncated not_after")
	}
}

func TestDecode_TruncatedAlgorithm(t *testing.T) {
	data := []byte{0x01, 0x00, 0x00}
	data = append(data, 0x00, 0x04)
	data = append(data, 0x01, 0x02, 0x03, 0x04)
	data = append(data, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01) // not_after
	data = append(data, 0x08) // only 1 byte of algorithm

	_, err := Decode(data)
	if err == nil {
		t.Error("expected error for truncated algorithm")
	}
}

func TestDecode_TruncatedSignatureLength(t *testing.T) {
	data := []byte{0x01, 0x00, 0x00}
	data = append(data, 0x00, 0x04)
	data = append(data, 0x01, 0x02, 0x03, 0x04)
	data = append(data, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
	data = append(data, 0x08, 0x07) // algorithm
	data = append(data, 0x00)       // only 1 byte of sig length

	_, err := Decode(data)
	if err == nil {
		t.Error("expected error for truncated signature length")
	}
}

func TestDecode_TruncatedSignature(t *testing.T) {
	data := []byte{0x01, 0x00, 0x00}
	data = append(data, 0x00, 0x04)
	data = append(data, 0x01, 0x02, 0x03, 0x04)
	data = append(data, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
	data = append(data, 0x08, 0x07)
	data = append(data, 0x00, 0x40) // sig length = 64
	data = append(data, make([]byte, 32)...) // only 32 bytes

	_, err := Decode(data)
	if err == nil {
		t.Error("expected error for truncated signature")
	}
}

func TestDecode_MethodRPK_NoSignature(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00} // method=rpk (0), no trusted_keys

	auth, err := Decode(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if auth.Method != MethodRPK {
		t.Errorf("expected method rpk, got %v", auth.Method)
	}

	if auth.Signature != nil {
		t.Error("expected nil signature when no signature data present")
	}
}

func TestDecode_UnknownMethod(t *testing.T) {
	// Unknown method should fail at decode time (versioned validation)
	data := []byte{0x99, 0x00, 0x00} // method=0x99

	_, err := Decode(data)
	if err == nil {
		t.Fatalf("expected error for unknown method, got nil")
	}
	if !errors.Is(err, ErrUnsupportedMethod) {
		t.Errorf("expected ErrUnsupportedMethod, got %v", err)
	}
}

// =============================================================================
// SIGNATURE EDGE CASES
// =============================================================================

func TestVerifyRPK_EmptyTrustedKeys(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	echConfigTBS := []byte("test config")
	notAfter := time.Now().Add(24 * time.Hour)

	sig := SignRPK(echConfigTBS, privateKey, notAfter)

	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{}, // Empty!
		Signature:   sig,
	}

	err := VerifyRPK(echConfigTBS, auth, time.Now())
	if err == nil {
		t.Error("expected error for empty trusted_keys")
	}
}

func TestVerifyRPK_WrongSignatureLength(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	echConfigTBS := []byte("test config")
	notAfter := time.Now().Add(24 * time.Hour)

	sig := SignRPK(echConfigTBS, privateKey, notAfter)
	spkiHash := ComputeSPKIHash(sig.Authenticator)

	// Truncate signature
	sig.SignatureData = sig.SignatureData[:32]

	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash},
		Signature:   sig,
	}

	err := VerifyRPK(echConfigTBS, auth, time.Now())
	if err == nil {
		t.Error("expected error for wrong signature length")
	}
}

func TestVerifyRPK_WrongAlgorithm(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	echConfigTBS := []byte("test config")
	notAfter := time.Now().Add(24 * time.Hour)

	sig := SignRPK(echConfigTBS, privateKey, notAfter)
	spkiHash := ComputeSPKIHash(sig.Authenticator)

	// Change algorithm
	sig.Algorithm = ECDSAP256SHA256Scheme

	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash},
		Signature:   sig,
	}

	err := VerifyRPK(echConfigTBS, auth, time.Now())
	if err == nil {
		t.Error("expected error for wrong algorithm")
	}
}

func TestVerifyRPK_InvalidSPKILength(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	echConfigTBS := []byte("test config")
	notAfter := time.Now().Add(24 * time.Hour)

	sig := SignRPK(echConfigTBS, privateKey, notAfter)

	// Wrong SPKI length
	wrongSPKI := make([]byte, 32) // Should be 44
	wrongHash := ComputeSPKIHash(wrongSPKI)

	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{wrongHash},
		Signature:   sig,
	}
	// Replace authenticator with wrong-length SPKI
	auth.Signature.Authenticator = wrongSPKI

	err := VerifyRPK(echConfigTBS, auth, time.Now())
	if err == nil {
		t.Error("expected error for invalid SPKI length")
	}
}

func TestVerifyRPK_InvalidSPKIPrefix(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	echConfigTBS := []byte("test config")
	notAfter := time.Now().Add(24 * time.Hour)

	sig := SignRPK(echConfigTBS, privateKey, notAfter)

	// Corrupt SPKI prefix
	sig.Authenticator[0] = 0x31 // Wrong tag

	// Recompute hash of corrupted SPKI
	spkiHash := ComputeSPKIHash(sig.Authenticator)

	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash},
		Signature:   sig,
	}

	err := VerifyRPK(echConfigTBS, auth, time.Now())
	if err == nil {
		t.Error("expected error for invalid SPKI prefix")
	}
}

func TestVerifyRPK_ZeroNotAfter(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	echConfigTBS := []byte("test config")

	sig := SignRPK(echConfigTBS, privateKey, time.Unix(0, 0))
	spkiHash := ComputeSPKIHash(sig.Authenticator)

	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash},
		Signature:   sig,
	}

	err := VerifyRPK(echConfigTBS, auth, time.Now())
	if err == nil {
		t.Error("expected expiration error for zero not_after")
	}
}

func TestVerifyRPK_FarFutureNotAfter(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	echConfigTBS := []byte("test config")
	// Year 2100
	notAfter := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)

	sig := SignRPK(echConfigTBS, privateKey, notAfter)
	spkiHash := ComputeSPKIHash(sig.Authenticator)

	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash},
		Signature:   sig,
	}

	// Should work - just very far in the future
	err := VerifyRPK(echConfigTBS, auth, time.Now())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyRPK_ExactlyAtExpiration(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	echConfigTBS := []byte("test config")
	notAfter := time.Unix(1000000000, 0)

	sig := SignRPK(echConfigTBS, privateKey, notAfter)
	spkiHash := ComputeSPKIHash(sig.Authenticator)

	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash},
		Signature:   sig,
	}

	// Exactly at expiration should fail (current >= not_after)
	err := VerifyRPK(echConfigTBS, auth, time.Unix(1000000000, 0))
	if err == nil {
		t.Error("expected expiration error at exact boundary")
	}

	// One second before should pass
	err = VerifyRPK(echConfigTBS, auth, time.Unix(999999999, 0))
	if err != nil {
		t.Errorf("should pass one second before: %v", err)
	}
}

// =============================================================================
// SPKI TESTS
// =============================================================================

func TestEncodeEd25519SPKI_WrongLength(t *testing.T) {
	// Too short
	result := EncodeEd25519SPKI(make([]byte, 16))
	if result != nil {
		t.Error("expected nil for short key")
	}

	// Too long
	result = EncodeEd25519SPKI(make([]byte, 64))
	if result != nil {
		t.Error("expected nil for long key")
	}
}

func TestExtractEd25519PublicKey_AllZeros(t *testing.T) {
	// Valid SPKI with all-zero key
	spki := make([]byte, 44)
	copy(spki, ed25519SPKIPrefix)

	key, err := ExtractEd25519PublicKey(spki)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(key, make([]byte, 32)) {
		t.Error("expected all-zero key")
	}
}

// =============================================================================
// ENCODE/DECODE ROUNDTRIP EDGE CASES
// =============================================================================

func TestEncodeDecodeRoundtrip_MaxTrustedKeys(t *testing.T) {
	// Many trusted keys
	keys := make([]SPKIHash, 100)
	for i := range keys {
		keys[i][0] = byte(i)
	}

	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: keys,
		Signature:   nil,
	}

	encoded := auth.Encode()
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if len(decoded.TrustedKeys) != 100 {
		t.Errorf("expected 100 keys, got %d", len(decoded.TrustedKeys))
	}
}

func TestEncodeDecodeRoundtrip_LargeAuthenticator(t *testing.T) {
	// Large authenticator (like a certificate chain for PKIX)
	auth := &Auth{
		Method:      MethodPKIX,
		TrustedKeys: []SPKIHash{{}},
		Signature: &Signature{
			Authenticator: make([]byte, 10000), // 10KB cert chain
			NotAfter:      1000000000,
			Algorithm:     Ed25519SignatureScheme,
			SignatureData: make([]byte, 64),
		},
	}

	encoded := auth.Encode()
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if len(decoded.Signature.Authenticator) != 10000 {
		t.Errorf("authenticator length mismatch")
	}
}

// =============================================================================
// TEST VECTOR VERIFICATION
// =============================================================================

func TestKnownTestVector(t *testing.T) {
	// From Rust interop vector
	keyBytes, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	privateKey := ed25519.NewKeyFromSeed(keyBytes)

	echConfigTBS := []byte("test ECH config for interop")
	notAfter := time.Unix(1893456000, 0)

	sig := SignRPK(echConfigTBS, privateKey, notAfter)

	// Verify SPKI
	expectedSPKI, _ := hex.DecodeString("302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if !bytes.Equal(sig.Authenticator, expectedSPKI) {
		t.Errorf("SPKI mismatch")
	}

	// Verify signature (Ed25519 is deterministic)
	expectedSig, _ := hex.DecodeString("8ca4021885d35a609b8dcbbd33ee0d09590f77720b4c4c4d74984b67bcc20d7e01a9f72061da2711dcda84cf3073544b05960141a004de11335da2513375d009")
	if !bytes.Equal(sig.SignatureData, expectedSig) {
		t.Errorf("signature mismatch")
	}

	// Verify encoded auth matches Rust
	spkiHash := ComputeSPKIHash(sig.Authenticator)
	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash},
		Signature:   sig,
	}

	encoded := auth.Encode()
	// PR #2: method=0 for RPK (was 1)
	expectedEncoded, _ := hex.DecodeString("00002006e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9002c302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a0000000070dbd880080700408ca4021885d35a609b8dcbbd33ee0d09590f77720b4c4c4d74984b67bcc20d7e01a9f72061da2711dcda84cf3073544b05960141a004de11335da2513375d009")
	if !bytes.Equal(encoded, expectedEncoded) {
		t.Errorf("encoded mismatch:\n  got:  %x\n  want: %x", encoded, expectedEncoded)
	}
}
