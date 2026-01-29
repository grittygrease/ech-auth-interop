// PKIX (certificate-based) authentication for ECH configs

package echauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// OID for id-pe-echConfigSigning extension (1.3.6.1.5.5.7.1.TBD)
// Using 99 for testing until IANA assigns the real value
var oidECHConfigSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 99}

// PKIX-specific errors
var (
	ErrChainValidation    = errors.New("echauth: certificate chain validation failed")
	ErrMissingECHSignExt  = errors.New("echauth: certificate missing id-pe-echConfigSigning extension")
	ErrExtNotCritical     = errors.New("echauth: id-pe-echConfigSigning extension must be critical")
	ErrSANMismatch        = errors.New("echauth: certificate SAN does not match public_name")
	ErrCertExpired        = errors.New("echauth: certificate expired")
	ErrEmptyCertChain     = errors.New("echauth: empty certificate chain")
	ErrInvalidCertificate = errors.New("echauth: invalid certificate")
)

// PKIXTrustAnchor holds root certificates for PKIX verification
type PKIXTrustAnchor struct {
	Roots *x509.CertPool
}

// NewPKIXTrustAnchor creates a trust anchor from DER-encoded root certificates
func NewPKIXTrustAnchor(rootCerts [][]byte) (*PKIXTrustAnchor, error) {
	pool := x509.NewCertPool()
	for _, der := range rootCerts {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
		}
		pool.AddCert(cert)
	}
	return &PKIXTrustAnchor{Roots: pool}, nil
}

// SignPKIX signs an ECHConfig using PKIX method with Ed25519
func SignPKIX(echConfigTBS []byte, privateKey ed25519.PrivateKey, certChain [][]byte) *Signature {
	// Encode certificate chain (TLS-style: 24-bit length prefix per cert)
	var authenticator []byte
	for _, cert := range certChain {
		// 24-bit length (3 bytes big-endian)
		lenBytes := []byte{
			byte(len(cert) >> 16),
			byte(len(cert) >> 8),
			byte(len(cert)),
		}
		authenticator = append(authenticator, lenBytes...)
		authenticator = append(authenticator, cert...)
	}

	// Build to_be_signed = context_label || ech_config_tbs
	toSign := make([]byte, len(ContextLabel)+len(echConfigTBS))
	copy(toSign, ContextLabel)
	copy(toSign[len(ContextLabel):], echConfigTBS)

	// Sign
	sig := ed25519.Sign(privateKey, toSign)

	return &Signature{
		Authenticator: authenticator,
		NotAfter:      0, // PKIX uses certificate validity, not this field
		Algorithm:     Ed25519SignatureScheme,
		SignatureData: sig,
	}
}

// VerifyPKIX verifies an ECHAuth extension with PKIX method
func VerifyPKIX(echConfigTBS []byte, auth *Auth, publicName string, anchor *PKIXTrustAnchor, now time.Time) error {
	// Step 1: Check method
	if auth.Method != MethodPKIX {
		return fmt.Errorf("%w: expected PKIX, got %v", ErrUnsupportedMethod, auth.Method)
	}

	// Step 2: Check signature exists
	if auth.Signature == nil {
		return ErrSignatureMissing
	}
	sig := auth.Signature

	// Step 3: Parse certificate chain
	certs, err := parseCertificateChain(sig.Authenticator)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return ErrEmptyCertChain
	}

	leaf := certs[0]

	// Step 4: Check for critical id-pe-echConfigSigning extension
	if err := checkECHSigningExtension(leaf); err != nil {
		return err
	}

	// Mark the ECH signing extension as handled (so x509.Verify doesn't reject it)
	// We need to filter it out of UnhandledCriticalExtensions
	var filteredUnhandled []asn1.ObjectIdentifier
	for _, oid := range leaf.UnhandledCriticalExtensions {
		if !oid.Equal(oidECHConfigSigning) {
			filteredUnhandled = append(filteredUnhandled, oid)
		}
	}
	leaf.UnhandledCriticalExtensions = filteredUnhandled

	// Step 5: Verify certificate chain
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         anchor.Roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		DNSName:       publicName, // This also checks SAN
	}

	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("%w: %v", ErrChainValidation, err)
	}

	// Step 6: Check algorithm matches certificate key type
	if sig.Algorithm != Ed25519SignatureScheme {
		return fmt.Errorf("%w: 0x%04x (only Ed25519 supported for PKIX)", ErrUnsupportedAlgo, sig.Algorithm)
	}

	pubKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("%w: certificate key type does not match signature algorithm", ErrInvalidCertificate)
	}

	// Step 7: Verify signature
	toSign := make([]byte, len(ContextLabel)+len(echConfigTBS))
	copy(toSign, ContextLabel)
	copy(toSign[len(ContextLabel):], echConfigTBS)

	if len(sig.SignatureData) != ed25519.SignatureSize {
		return ErrSignatureInvalid
	}

	if !ed25519.Verify(pubKey, toSign, sig.SignatureData) {
		return ErrSignatureInvalid
	}

	return nil
}

// parseCertificateChain parses TLS-style certificate chain (24-bit length prefix)
func parseCertificateChain(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	offset := 0

	for offset < len(data) {
		if len(data) < offset+3 {
			return nil, fmt.Errorf("%w: truncated certificate length", ErrDecode)
		}

		// 24-bit length (big-endian)
		certLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
		offset += 3

		if len(data) < offset+certLen {
			return nil, fmt.Errorf("%w: truncated certificate data", ErrDecode)
		}

		cert, err := x509.ParseCertificate(data[offset : offset+certLen])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
		}

		certs = append(certs, cert)
		offset += certLen
	}

	return certs, nil
}

// checkECHSigningExtension verifies the certificate has the critical ECH signing extension
func checkECHSigningExtension(cert *x509.Certificate) error {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidECHConfigSigning) {
			if !ext.Critical {
				return ErrExtNotCritical
			}
			return nil
		}
	}
	return ErrMissingECHSignExt
}

// EncodeCertificateChain encodes certificates in TLS wire format (24-bit length prefix)
func EncodeCertificateChain(certs []*x509.Certificate) []byte {
	var result []byte
	for _, cert := range certs {
		der := cert.Raw
		// 24-bit length
		lenBytes := []byte{
			byte(len(der) >> 16),
			byte(len(der) >> 8),
			byte(len(der)),
		}
		result = append(result, lenBytes...)
		result = append(result, der...)
	}
	return result
}

// Helper for tests: create a self-signed certificate with ECH signing extension
func CreateECHSigningCert(privateKey ed25519.PrivateKey, publicName string, notBefore, notAfter time.Time) ([]byte, error) {
	publicKey := privateKey.Public().(ed25519.PublicKey)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: publicName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		DNSNames:              []string{publicName},
		// Add critical ECH signing extension
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidECHConfigSigning,
				Critical: true,
				Value:    []byte{0x05, 0x00}, // NULL
			},
		},
	}

	return x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
}
