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

// createTestCert creates a certificate for testing
func createTestCert(t *testing.T, privateKey ed25519.PrivateKey, publicName string,
	notBefore, notAfter time.Time, isCA bool, includeECHExt bool, criticalECHExt bool,
	parent *x509.Certificate, parentKey ed25519.PrivateKey) *x509.Certificate {
	t.Helper()

	publicKey := privateKey.Public().(ed25519.PublicKey)

	keyUsage := x509.KeyUsageDigitalSignature
	if isCA {
		keyUsage |= x509.KeyUsageCertSign
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: publicName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              []string{publicName},
	}

	if includeECHExt {
		template.ExtraExtensions = []pkix.Extension{
			{
				Id:       oidECHConfigSigning,
				Critical: criticalECHExt,
				Value:    []byte{0x05, 0x00}, // ASN.1 NULL
			},
		}
	}

	signer := parent
	signerKey := parentKey
	if signer == nil {
		signer = template
		signerKey = privateKey
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, signer, publicKey, signerKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func TestVerifyPKIX_Valid(t *testing.T) {
	// Generate CA key and cert
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)

	caCert := createTestCert(t, caKey, "Test CA", notBefore, notAfter, true, false, false, nil, nil)

	// Generate leaf key and cert with ECH extension
	_, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	leafCert := createTestCert(t, leafKey, "example.com", notBefore, notAfter, false, true, true, caCert, caKey)

	// Create trust anchor
	anchor, err := NewPKIXTrustAnchor([][]byte{caCert.Raw})
	if err != nil {
		t.Fatalf("failed to create trust anchor: %v", err)
	}

	// Sign ECH config
	echConfigTBS := []byte("test ECH config for PKIX")
	sig := SignPKIX(echConfigTBS, leafKey, [][]byte{leafCert.Raw}, notAfter)

	// Build Auth
	auth := &Auth{
		Method:      MethodPKIX,
		TrustedKeys: nil, // Not used for PKIX
		Signature:   sig,
	}

	// Verify
	err = VerifyPKIX(echConfigTBS, auth, "example.com", anchor, time.Now())
	if err != nil {
		t.Errorf("verification failed: %v", err)
	}
}

func TestVerifyPKIX_MissingECHExtension(t *testing.T) {
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)

	caCert := createTestCert(t, caKey, "Test CA", notBefore, notAfter, true, false, false, nil, nil)

	// Leaf cert WITHOUT ECH extension
	_, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	leafCert := createTestCert(t, leafKey, "example.com", notBefore, notAfter, false, false, false, caCert, caKey)

	anchor, _ := NewPKIXTrustAnchor([][]byte{caCert.Raw})

	echConfigTBS := []byte("test config")
	sig := SignPKIX(echConfigTBS, leafKey, [][]byte{leafCert.Raw}, notAfter)

	auth := &Auth{
		Method:    MethodPKIX,
		Signature: sig,
	}

	err := VerifyPKIX(echConfigTBS, auth, "example.com", anchor, time.Now())
	if err == nil {
		t.Error("expected error for missing ECH extension")
	}
	if err != ErrMissingECHSignExt {
		t.Errorf("expected ErrMissingECHSignExt, got: %v", err)
	}
}

func TestVerifyPKIX_NonCriticalECHExtension(t *testing.T) {
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)

	caCert := createTestCert(t, caKey, "Test CA", notBefore, notAfter, true, false, false, nil, nil)

	// Leaf cert with NON-CRITICAL ECH extension
	_, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	leafCert := createTestCert(t, leafKey, "example.com", notBefore, notAfter, false, true, false, caCert, caKey)

	anchor, _ := NewPKIXTrustAnchor([][]byte{caCert.Raw})

	echConfigTBS := []byte("test config")
	sig := SignPKIX(echConfigTBS, leafKey, [][]byte{leafCert.Raw}, notAfter)

	auth := &Auth{
		Method:    MethodPKIX,
		Signature: sig,
	}

	err := VerifyPKIX(echConfigTBS, auth, "example.com", anchor, time.Now())
	if err == nil {
		t.Error("expected error for non-critical ECH extension")
	}
	if err != ErrExtNotCritical {
		t.Errorf("expected ErrExtNotCritical, got: %v", err)
	}
}

func TestVerifyPKIX_ExpiredCert(t *testing.T) {
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	notBefore := time.Now().Add(-48 * time.Hour)
	notAfter := time.Now().Add(-24 * time.Hour) // Expired!

	caCert := createTestCert(t, caKey, "Test CA", notBefore, time.Now().Add(24*time.Hour), true, false, false, nil, nil)

	_, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	leafCert := createTestCert(t, leafKey, "example.com", notBefore, notAfter, false, true, true, caCert, caKey)

	anchor, _ := NewPKIXTrustAnchor([][]byte{caCert.Raw})

	echConfigTBS := []byte("test config")
	sig := SignPKIX(echConfigTBS, leafKey, [][]byte{leafCert.Raw}, notAfter)

	auth := &Auth{
		Method:    MethodPKIX,
		Signature: sig,
	}

	err := VerifyPKIX(echConfigTBS, auth, "example.com", anchor, time.Now())
	if err == nil {
		t.Error("expected error for expired certificate")
	}
}

func TestVerifyPKIX_UntrustedRoot(t *testing.T) {
	// Create cert signed by unknown CA
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)

	caCert := createTestCert(t, caKey, "Unknown CA", notBefore, notAfter, true, false, false, nil, nil)

	_, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	leafCert := createTestCert(t, leafKey, "example.com", notBefore, notAfter, false, true, true, caCert, caKey)

	// Trust anchor with DIFFERENT CA
	_, otherCAKey, _ := ed25519.GenerateKey(rand.Reader)
	otherCACert := createTestCert(t, otherCAKey, "Other CA", notBefore, notAfter, true, false, false, nil, nil)
	anchor, _ := NewPKIXTrustAnchor([][]byte{otherCACert.Raw})

	echConfigTBS := []byte("test config")
	sig := SignPKIX(echConfigTBS, leafKey, [][]byte{leafCert.Raw}, notAfter)

	auth := &Auth{
		Method:    MethodPKIX,
		Signature: sig,
	}

	err := VerifyPKIX(echConfigTBS, auth, "example.com", anchor, time.Now())
	if err == nil {
		t.Error("expected error for untrusted root")
	}
}

func TestVerifyPKIX_SANMismatch(t *testing.T) {
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)

	caCert := createTestCert(t, caKey, "Test CA", notBefore, notAfter, true, false, false, nil, nil)

	_, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	// Cert is for "example.com" but we'll verify against "other.com"
	leafCert := createTestCert(t, leafKey, "example.com", notBefore, notAfter, false, true, true, caCert, caKey)

	anchor, _ := NewPKIXTrustAnchor([][]byte{caCert.Raw})

	echConfigTBS := []byte("test config")
	sig := SignPKIX(echConfigTBS, leafKey, [][]byte{leafCert.Raw}, notAfter)

	auth := &Auth{
		Method:    MethodPKIX,
		Signature: sig,
	}

	// Verify with wrong public_name
	err := VerifyPKIX(echConfigTBS, auth, "other.com", anchor, time.Now())
	if err == nil {
		t.Error("expected error for SAN mismatch")
	}
}

func TestVerifyPKIX_WrongSignature(t *testing.T) {
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)

	caCert := createTestCert(t, caKey, "Test CA", notBefore, notAfter, true, false, false, nil, nil)

	_, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	leafCert := createTestCert(t, leafKey, "example.com", notBefore, notAfter, false, true, true, caCert, caKey)

	anchor, _ := NewPKIXTrustAnchor([][]byte{caCert.Raw})

	echConfigTBS := []byte("test config")
	sig := SignPKIX(echConfigTBS, leafKey, [][]byte{leafCert.Raw}, notAfter)

	// Corrupt signature
	sig.SignatureData[0] ^= 0xff

	auth := &Auth{
		Method:    MethodPKIX,
		Signature: sig,
	}

	err := VerifyPKIX(echConfigTBS, auth, "example.com", anchor, time.Now())
	if err == nil {
		t.Error("expected error for wrong signature")
	}
	if err != ErrSignatureInvalid {
		t.Errorf("expected ErrSignatureInvalid, got: %v", err)
	}
}

func TestVerifyPKIX_WrongMethod(t *testing.T) {
	auth := &Auth{
		Method:    MethodRPK,
		Signature: &Signature{},
	}

	err := VerifyPKIX([]byte("test"), auth, "example.com", &PKIXTrustAnchor{}, time.Now())
	if err == nil {
		t.Error("expected error for wrong method")
	}
}

func TestVerifyPKIX_EmptyChain(t *testing.T) {
	auth := &Auth{
		Method: MethodPKIX,
		Signature: &Signature{
			Authenticator: []byte{}, // Empty chain
			Algorithm:     Ed25519SignatureScheme,
			SignatureData: make([]byte, 64),
		},
	}

	err := VerifyPKIX([]byte("test"), auth, "example.com", &PKIXTrustAnchor{}, time.Now())
	if err == nil {
		t.Error("expected error for empty chain")
	}
}

func TestVerifyPKIX_TruncatedChain(t *testing.T) {
	// Chain with length prefix but no data
	auth := &Auth{
		Method: MethodPKIX,
		Signature: &Signature{
			Authenticator: []byte{0x00, 0x01, 0x00}, // says 256 bytes but only has header
			Algorithm:     Ed25519SignatureScheme,
			SignatureData: make([]byte, 64),
		},
	}

	err := VerifyPKIX([]byte("test"), auth, "example.com", &PKIXTrustAnchor{}, time.Now())
	if err == nil {
		t.Error("expected error for truncated chain")
	}
}

func TestParseCertificateChain(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	cert := createTestCert(t, key, "test.com",
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
		false, false, false, nil, nil)

	// Encode chain
	chain := EncodeCertificateChain([]*x509.Certificate{cert})

	// Parse it back
	parsed, err := parseCertificateChain(chain)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(parsed) != 1 {
		t.Errorf("expected 1 cert, got %d", len(parsed))
	}

	if parsed[0].Subject.CommonName != "test.com" {
		t.Errorf("wrong CN: %s", parsed[0].Subject.CommonName)
	}
}

func TestParseCertificateChain_MultipleCerts(t *testing.T) {
	_, key1, _ := ed25519.GenerateKey(rand.Reader)
	_, key2, _ := ed25519.GenerateKey(rand.Reader)

	cert1 := createTestCert(t, key1, "leaf.com",
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
		false, false, false, nil, nil)
	cert2 := createTestCert(t, key2, "intermediate.com",
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
		true, false, false, nil, nil)

	chain := EncodeCertificateChain([]*x509.Certificate{cert1, cert2})

	parsed, err := parseCertificateChain(chain)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(parsed) != 2 {
		t.Errorf("expected 2 certs, got %d", len(parsed))
	}
}

func TestCheckECHSigningExtension(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)

	// With critical extension
	certWithExt := createTestCert(t, key, "test.com",
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
		false, true, true, nil, nil)
	if err := checkECHSigningExtension(certWithExt); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Without extension
	certWithoutExt := createTestCert(t, key, "test.com",
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
		false, false, false, nil, nil)
	if err := checkECHSigningExtension(certWithoutExt); err != ErrMissingECHSignExt {
		t.Errorf("expected ErrMissingECHSignExt, got: %v", err)
	}

	// With non-critical extension
	certNonCritical := createTestCert(t, key, "test.com",
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
		false, true, false, nil, nil)
	if err := checkECHSigningExtension(certNonCritical); err != ErrExtNotCritical {
		t.Errorf("expected ErrExtNotCritical, got: %v", err)
	}
}
