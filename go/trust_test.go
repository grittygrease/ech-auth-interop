// trust_test.go - Comprehensive tests for ECH auth trust model
package echauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// ============================================================================
// Test Helpers
// ============================================================================

func generateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return pub, priv
}

func createTestECHConfig(t *testing.T, publicName string) *ECHConfig {
	return &ECHConfig{
		Version:    ECHConfigVersion,
		ConfigID:   1,
		KemID:      0x0020,
		PublicKey:  make([]byte, 32),
		Ciphers:    []CipherSuite{{KdfID: 0x0001, AeadID: 0x0001}},
		MaxNameLen: 0,
		PublicName: []byte(publicName),
		Extensions: []Extension{},
	}
}

func signConfigRPK(t *testing.T, config *ECHConfig, privateKey ed25519.PrivateKey, notAfter time.Time) *Auth {
	spki := EncodeEd25519SPKI(privateKey.Public().(ed25519.PublicKey))
	placeholderSig := &Signature{
		Authenticator: spki,
		NotAfter:      uint64(notAfter.Unix()),
		Algorithm:     Ed25519SignatureScheme,
		SignatureData: make([]byte, ed25519.SignatureSize),
	}
	placeholderAuth := &Auth{
		Method:    MethodRPK,
		Signature: placeholderSig,
	}
	// Replace or append
	found := false
	for i := range config.Extensions {
		if config.Extensions[i].Type == ECHAuthExtensionType {
			config.Extensions[i].Data = placeholderAuth.Encode()
			found = true
			break
		}
	}
	if !found {
		config.Extensions = append(config.Extensions, Extension{
			Type: ECHAuthExtensionType,
			Data: placeholderAuth.Encode(),
		})
	}

	tbs, err := config.ComputeTBS()
	if err != nil {
		t.Fatalf("compute TBS: %v", err)
	}

	sig := SignRPK(tbs, privateKey, notAfter)
	auth := &Auth{
		Method:    MethodRPK,
		Signature: sig,
	}
	for i := range config.Extensions {
		if config.Extensions[i].Type == ECHAuthExtensionType {
			config.Extensions[i].Data = auth.Encode()
			break
		}
	}
	return auth
}

func signConfigPKIX(t *testing.T, config *ECHConfig, privateKey ed25519.PrivateKey, cert *x509.Certificate, notAfter time.Time) *Auth {
	// Encode as chain for placeholder too, so TBS matches
	var authChain []byte
	lenBytes := []byte{byte(len(cert.Raw) >> 16), byte(len(cert.Raw) >> 8), byte(len(cert.Raw))}
	authChain = append(authChain, lenBytes...)
	authChain = append(authChain, cert.Raw...)

	placeholderSig := &Signature{
		Authenticator: authChain,
		NotAfter:      uint64(notAfter.Unix()),
		Algorithm:     Ed25519SignatureScheme,
		SignatureData: make([]byte, ed25519.SignatureSize),
	}
	placeholderAuth := &Auth{
		Method:    MethodPKIX,
		Signature: placeholderSig,
	}

	found := false
	for i := range config.Extensions {
		if config.Extensions[i].Type == ECHAuthExtensionType {
			config.Extensions[i].Data = placeholderAuth.Encode()
			found = true
			break
		}
	}
	if !found {
		config.Extensions = append(config.Extensions, Extension{
			Type: ECHAuthExtensionType,
			Data: placeholderAuth.Encode(),
		})
	}

	tbs, err := config.ComputeTBS()
	if err != nil {
		t.Fatalf("compute TBS: %v", err)
	}

	sig := SignPKIX(tbs, privateKey, [][]byte{cert.Raw}, notAfter)
	auth := &Auth{
		Method:    MethodPKIX,
		Signature: sig,
	}
	for i := range config.Extensions {
		if config.Extensions[i].Type == ECHAuthExtensionType {
			config.Extensions[i].Data = auth.Encode()
			break
		}
	}
	return auth
}

func createSimpleTestCert(t *testing.T, privateKey ed25519.PrivateKey, publicName string, validFor time.Duration) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ECH Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{publicName},
		IsCA:         true,
	}

	echOID := []int{1, 3, 6, 1, 5, 5, 7, 1, 99}
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       echOID,
		Critical: true,
		Value:    []byte{0x05, 0x00}, // ASN.1 NULL
	})

	pubKey := privateKey.Public()
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privateKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

// ============================================================================
// Category A: RPK Trust Model Tests
// ============================================================================

func TestRPK_DNSProvisionedValid(t *testing.T) {
	_, priv := generateTestKeyPair(t)
	config := createTestECHConfig(t, "example.com")
	notAfter := time.Now().Add(24 * time.Hour)
	auth := signConfigRPK(t, config, priv, notAfter)

	spki := EncodeEd25519SPKI(priv.Public().(ed25519.PublicKey))
	anchor := ComputeSPKIHash(spki)

	result := EvaluateTrust(&EvaluateTrustInput{
		Config:         config,
		Auth:           auth,
		FromDNS:        true,
		DNSConfirmsECH: true,
		DNSRPKAnchor:   &anchor,
		Now:            time.Now(),
	})

	if result.Decision != TrustDecisionAccept {
		t.Errorf("expected Accept, got %v: %s", result.Decision, result.Reason)
	}
}

func TestRPK_DNSProvisionedMismatch(t *testing.T) {
	_, priv := generateTestKeyPair(t)
	_, wrongPriv := generateTestKeyPair(t)
	config := createTestECHConfig(t, "example.com")
	auth := signConfigRPK(t, config, priv, time.Now().Add(time.Hour))

	wrongSpki := EncodeEd25519SPKI(wrongPriv.Public().(ed25519.PublicKey))
	wrongAnchor := ComputeSPKIHash(wrongSpki)

	result := EvaluateTrust(&EvaluateTrustInput{
		Config:         config,
		Auth:           auth,
		FromDNS:        true,
		DNSConfirmsECH: true,
		DNSRPKAnchor:   &wrongAnchor,
		Now:            time.Now(),
	})

	if result.Decision != TrustDecisionReject {
		t.Errorf("expected Reject, got %v", result.Decision)
	}
}

func TestRPK_NoDNS_NewDomain(t *testing.T) {
	_, priv := generateTestKeyPair(t)
	config := createTestECHConfig(t, "example.com")
	auth := signConfigRPK(t, config, priv, time.Now().Add(time.Hour))

	result := EvaluateTrust(&EvaluateTrustInput{
		Config:       config,
		Auth:         auth,
		FromDNS:      false,
		DNSRPKAnchor: nil,
		Now:          time.Now(),
	})

	if result.Decision != TrustDecisionGREASE {
		t.Errorf("expected GREASE, got %v", result.Decision)
	}
}

func TestRPK_CachedFromRetry_NoDNS(t *testing.T) {
	_, priv := generateTestKeyPair(t)
	config := createTestECHConfig(t, "example.com")
	auth := signConfigRPK(t, config, priv, time.Now().Add(time.Hour))

	result := EvaluateTrust(&EvaluateTrustInput{
		Config:         config,
		Auth:           auth,
		FromDNS:        false,
		DNSConfirmsECH: false,
		DNSRPKAnchor:   nil,
		Now:            time.Now(),
	})

	if result.Decision != TrustDecisionGREASE {
		t.Errorf("expected GREASE, got %v", result.Decision)
	}
}

func TestRPK_ExpiredSignature(t *testing.T) {
	_, priv := generateTestKeyPair(t)
	config := createTestECHConfig(t, "example.com")
	auth := signConfigRPK(t, config, priv, time.Now().Add(-time.Hour))

	spki := EncodeEd25519SPKI(priv.Public().(ed25519.PublicKey))
	anchor := ComputeSPKIHash(spki)

	result := EvaluateTrust(&EvaluateTrustInput{
		Config:       config,
		Auth:         auth,
		FromDNS:      true,
		DNSRPKAnchor: &anchor,
		Now:          time.Now(),
	})

	if result.Decision != TrustDecisionReject {
		t.Errorf("expected Reject, got %v", result.Decision)
	}
}

// ============================================================================
// Category B: PKIX Trust Model Tests
// ============================================================================

func TestPKIX_ValidCert_DNSConfirmed(t *testing.T) {
	_, priv := generateTestKeyPair(t)
	cert := createSimpleTestCert(t, priv, "example.com", 24*time.Hour)
	config := createTestECHConfig(t, "example.com")
	notAfter := time.Now().Add(time.Hour)
	auth := signConfigPKIX(t, config, priv, cert, notAfter)

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	anchor := &PKIXTrustAnchor{Roots: roots}

	result := EvaluateTrust(&EvaluateTrustInput{
		Config:         config,
		Auth:           auth,
		FromDNS:        true,
		DNSConfirmsECH: true,
		PKIXRoots:      anchor,
		Now:            time.Now(),
	})

	if result.Decision != TrustDecisionAccept {
		t.Errorf("expected Accept, got %v: %s", result.Decision, result.Reason)
	}
}

func TestPKIX_ValidCert_NoDNS(t *testing.T) {
	_, priv := generateTestKeyPair(t)
	cert := createSimpleTestCert(t, priv, "example.com", 24*time.Hour)
	config := createTestECHConfig(t, "example.com")
	notAfter := time.Now().Add(time.Hour)
	auth := signConfigPKIX(t, config, priv, cert, notAfter)

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	anchor := &PKIXTrustAnchor{Roots: roots}

	result := EvaluateTrust(&EvaluateTrustInput{
		Config:         config,
		Auth:           auth,
		FromDNS:        false,
		DNSConfirmsECH: false,
		PKIXRoots:      anchor,
		Now:            time.Now(),
	})

	if result.Decision != TrustDecisionGREASE {
		t.Errorf("expected GREASE, got %v", result.Decision)
	}
}

func TestPKIX_NewDomain_ValidCert(t *testing.T) {
	_, priv := generateTestKeyPair(t)
	cert := createSimpleTestCert(t, priv, "new.com", 24*time.Hour)
	config := createTestECHConfig(t, "new.com")
	notAfter := time.Now().Add(time.Hour)
	auth := signConfigPKIX(t, config, priv, cert, notAfter)

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	anchor := &PKIXTrustAnchor{Roots: roots}

	result := EvaluateTrust(&EvaluateTrustInput{
		Config:    config,
		Auth:      auth,
		PKIXRoots: anchor,
		Now:       time.Now(),
	})

	if result.Decision != TrustDecisionGREASE {
		t.Errorf("expected GREASE, got %v", result.Decision)
	}
}

func TestPKIX_CertMissingSAN(t *testing.T) {
	_, priv := generateTestKeyPair(t)
	cert := createSimpleTestCert(t, priv, "wrong.com", 24*time.Hour)
	config := createTestECHConfig(t, "real.com")
	notAfter := time.Now().Add(time.Hour)
	auth := signConfigPKIX(t, config, priv, cert, notAfter)

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	anchor := &PKIXTrustAnchor{Roots: roots}

	result := EvaluateTrust(&EvaluateTrustInput{
		Config:    config,
		Auth:      auth,
		PKIXRoots: anchor,
		Now:       time.Now(),
	})

	if result.Decision != TrustDecisionReject {
		t.Errorf("expected Reject, got %v", result.Decision)
	}
}

func TestPKIX_CertExpired(t *testing.T) {
	_, priv := generateTestKeyPair(t)
	cert := createSimpleTestCert(t, priv, "example.com", -time.Hour)
	config := createTestECHConfig(t, "example.com")
	notAfter := time.Now().Add(time.Hour)
	auth := signConfigPKIX(t, config, priv, cert, notAfter)

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	anchor := &PKIXTrustAnchor{Roots: roots}

	result := EvaluateTrust(&EvaluateTrustInput{
		Config:    config,
		Auth:      auth,
		PKIXRoots: anchor,
		Now:       time.Now(),
	})

	if result.Decision != TrustDecisionReject {
		t.Errorf("expected Reject, got %v", result.Decision)
	}
}

func TestPKIX_CertUntrustedRoot(t *testing.T) {
	_, priv := generateTestKeyPair(t)
	_, untrustedPriv := generateTestKeyPair(t)
	cert := createSimpleTestCert(t, priv, "example.com", 24*time.Hour)
	untrustedCert := createSimpleTestCert(t, untrustedPriv, "ca.com", 24*time.Hour)
	config := createTestECHConfig(t, "example.com")
	notAfter := time.Now().Add(time.Hour)
	auth := signConfigPKIX(t, config, priv, cert, notAfter)

	roots := x509.NewCertPool()
	roots.AddCert(untrustedCert) // Different root
	anchor := &PKIXTrustAnchor{Roots: roots}

	result := EvaluateTrust(&EvaluateTrustInput{
		Config:    config,
		Auth:      auth,
		PKIXRoots: anchor,
		Now:       time.Now(),
	})

	if result.Decision != TrustDecisionReject {
		t.Errorf("expected Reject, got %v", result.Decision)
	}
}

// ============================================================================
// Category C: Outer SNI Scenarios
// ============================================================================

func TestOuterSNI_Mismatch_PKIXValid(t *testing.T) {
	_, priv := generateTestKeyPair(t)
	cert := createSimpleTestCert(t, priv, "real.com", 24*time.Hour)
	config := createTestECHConfig(t, "real.com")
	notAfter := time.Now().Add(time.Hour)
	auth := signConfigPKIX(t, config, priv, cert, notAfter)

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	anchor := &PKIXTrustAnchor{Roots: roots}

	result := EvaluateTrust(&EvaluateTrustInput{
		Config:    config,
		Auth:      auth,
		PKIXRoots: anchor,
		Now:       time.Now(),
	})

	if result.ValidatedConfig == nil || result.ValidatedConfig.PublicName != "real.com" {
		t.Error("should cache valid config from retry")
	}
}

func TestOuterSNI_Mismatch_RPKNoDNS(t *testing.T) {
	_, priv := generateTestKeyPair(t)
	config := createTestECHConfig(t, "real.com")
	auth := signConfigRPK(t, config, priv, time.Now().Add(time.Hour))

	result := EvaluateTrust(&EvaluateTrustInput{
		Config:       config,
		Auth:         auth,
		DNSRPKAnchor: nil,
		Now:          time.Now(),
	})

	if result.Decision != TrustDecisionGREASE {
		t.Errorf("expected GREASE, got %v", result.Decision)
	}
}

// ============================================================================
// Category D: Update/Rotation Scenarios
// ============================================================================

func TestUpdate_SamePublicName_NewKey(t *testing.T) {
	_, newPriv := generateTestKeyPair(t)
	newSpki := EncodeEd25519SPKI(newPriv.Public().(ed25519.PublicKey))
	newAnchor := ComputeSPKIHash(newSpki)

	config := createTestECHConfig(t, "example.com")
	auth := signConfigRPK(t, config, newPriv, time.Now().Add(time.Hour))

	result := EvaluateTrust(&EvaluateTrustInput{
		Config:         config,
		Auth:           auth,
		FromDNS:        true,
		DNSConfirmsECH: true,
		DNSRPKAnchor:   &newAnchor,
		Now:            time.Now(),
	})

	if result.Decision != TrustDecisionAccept {
		t.Errorf("expected Accept, got %v", result.Decision)
	}
}

func TestUpdate_Downgrade_Unsigned(t *testing.T) {
	cache := NewConfigCache()
	cache.Put(&CachedConfig{
		PublicName: "example.com",
		Auth:       &Auth{Method: MethodRPK},
	})

	if !cache.ShouldRejectDowngrade("example.com", nil) {
		t.Error("should reject downgrade")
	}
}

func TestNoAuthExtension_GREASE(t *testing.T) {
	config := createTestECHConfig(t, "example.com")
	result := EvaluateTrust(&EvaluateTrustInput{
		Config: config,
		Auth:   nil,
		Now:    time.Now(),
	})

	if result.Decision != TrustDecisionGREASE {
		t.Errorf("expected GREASE, got %v", result.Decision)
	}
}
