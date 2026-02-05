//go:build e2e

package echauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// Helper to wrapping config in list [ListLen 2][Config...]
func wrapInList(cfg []byte) []byte {
	var list []byte
	list = append(list, byte(len(cfg)>>8), byte(len(cfg)))
	list = append(list, cfg...)
	return list
}

func addExt(cfg []byte, typ uint16, dat []byte) []byte {
	if len(cfg) < 4 {
		return cfg
	}
	contents := cfg[4:]
	if len(contents) < 2 {
		return cfg
	}
	payload := contents[:len(contents)-2] // strip last 2 bytes (assuming ExtLen=0)

	newExtLen := 4 + len(dat)
	var newContents []byte
	newContents = append(newContents, payload...)
	newContents = append(newContents, byte(newExtLen>>8), byte(newExtLen))
	newContents = append(newContents, byte(typ>>8), byte(typ))
	newContents = append(newContents, byte(len(dat)>>8), byte(len(dat)))
	newContents = append(newContents, dat...)

	var newCfg []byte
	newCfg = append(newCfg, cfg[0:2]...)
	newCfg = append(newCfg, byte(len(newContents)>>8), byte(len(newContents)))
	newCfg = append(newCfg, newContents...)
	return newCfg
}

func TestSignedECH_Lifecycle(t *testing.T) {
	// 1. Generate Base Keys
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Generate ECH Config
	baseConfigTBS, _, err := generateECHConfig(1, "signed.example.com")
	if err != nil {
		t.Fatal(err)
	}

	// 3. Prepare Config with Zeroed Extension (TBS)
	now := time.Now()
	oneHour := time.Hour
	dummySig := &Signature{
		Authenticator: EncodeEd25519SPKI(pubKey),
		NotAfter:      uint64(now.Add(oneHour).Unix()),
		Algorithm:     Ed25519SignatureScheme,
		SignatureData: make([]byte, ed25519.SignatureSize), // Zeroed signature
	}

	tbsAuth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{ComputeSPKIHash(dummySig.Authenticator)},
		Signature:   dummySig,
	}

	// Encode and add "zeroed" extension
	extData := tbsAuth.Encode()
	tbsBytes := addExt(baseConfigTBS, ECHAuthExtensionType, extData)

	// 4. Sign the TBS Bytes (Context || Config)
	toSign := make([]byte, len(ContextLabel)+len(tbsBytes))
	copy(toSign, ContextLabel)
	copy(toSign[len(ContextLabel):], tbsBytes)
	signatureBytes := ed25519.Sign(privKey, toSign)

	// 5. Create Final Extension with Real Signature
	finalSig := &Signature{
		Authenticator: dummySig.Authenticator,
		NotAfter:      dummySig.NotAfter,
		Algorithm:     dummySig.Algorithm,
		SignatureData: signatureBytes,
	}
	finalAuth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: tbsAuth.TrustedKeys,
		Signature:   finalSig,
	}

	finalExtData := finalAuth.Encode()
	signedConfigBytes := addExt(baseConfigTBS, ECHAuthExtensionType, finalExtData)

	// 6. Verify Valid Config
	anchor := &TrustAnchor{
		TrustedKeys: []SPKIHash{ComputeSPKIHash(EncodeEd25519SPKI(pubKey))},
	}
	timeFunc := func() uint64 { return uint64(now.Unix()) }

	configs, err := VerifyConfigList(wrapInList(signedConfigBytes), anchor, timeFunc)
	if err != nil {
		t.Fatalf("Valid config failed verification: %v", err)
	}
	if len(configs) != 1 {
		t.Errorf("Expected 1 verified config, got %d", len(configs))
	}

	// Check extension presence
	authExt, err := configs[0].GetAuthExtension()
	if err != nil {
		t.Errorf("Failed to retrieve auth extension from verified config: %v", err)
	}
	if authExt.Method != MethodRPK {
		t.Errorf("Expected MethodRPK, got %v", authExt.Method)
	}

	// 7. Test Failure: Tampered Signature
	tamperedBytes := make([]byte, len(signedConfigBytes))
	copy(tamperedBytes, signedConfigBytes)
	tamperedBytes[len(tamperedBytes)-1] ^= 0xFF // Flip last byte

	_, err = VerifyConfigList(wrapInList(tamperedBytes), anchor, timeFunc)
	if err != ErrSignatureInvalid {
		t.Errorf("Expected ErrSignatureInvalid for tampered sig, got: %v", err)
	}

	// 8. Test Failure: Expired
	futureTimeFunc := func() uint64 { return uint64(now.Add(2 * time.Hour).Unix()) }
	_, err = VerifyConfigList(wrapInList(signedConfigBytes), anchor, futureTimeFunc)
	// ErrExpired is usually wrapped or returned directly depending on VerifyRPK implementation
	if err == nil {
		t.Error("Expected error for expired config, got nil")
	} else {
		// Just ensure it failed
		t.Logf("Expired config correctly rejected: %v", err)
	}
}

func TestWireFormat_Versions(t *testing.T) {
	// Create a simple Auth struct (RPK)
	authRPK := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{{0xAB, 0xCD}}, // Dummy key
	}

	// PR #2 (RPK=0x00)
	wirePR2 := authRPK.EncodeVersioned(SpecPR2)
	if wirePR2[0] != 0x00 {
		t.Errorf("PR#2 RPK: expected 0x00, got 0x%02x", wirePR2[0])
	}
	if ver, ok := DetectVersion(wirePR2); !ok || ver != SpecPR2 {
		t.Errorf("PR#2 Detection failed: val=%d ok=%v", ver, ok)
	}

	// Published (RPK=0x01)
	wirePub := authRPK.EncodeVersioned(SpecPublished)
	if wirePub[0] != 0x01 {
		t.Errorf("Published RPK: expected 0x01, got 0x%02x", wirePub[0])
	}
	// 0x01 is ambiguous for detection (PR2 PKIX vs Pub RPK), so detection should fail
	if _, ok := DetectVersion(wirePub); ok {
		t.Error("Published RPK (0x01) should be ambiguous detection, but got OK")
	}
}
