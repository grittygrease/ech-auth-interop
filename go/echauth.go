// Package echauth implements authenticated ECH config distribution
// per draft-sullivan-tls-signed-ech-updates.
package echauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Context label for ECH authentication signatures
const ContextLabel = "TLS-ECH-AUTH-v1"

// Signature scheme identifiers (TLS SignatureScheme registry)
const (
	Ed25519SignatureScheme      uint16 = 0x0807
	ECDSAP256SHA256Scheme       uint16 = 0x0403
)

// ECH Auth extension type (use 0xff01 for testing, TBD in final spec)
const ECHAuthExtensionType uint16 = 0xff01

// Method identifies the authentication method
type Method uint8

const (
	MethodNone Method = 0
	MethodRPK  Method = 1
	MethodPKIX Method = 2
)

func (m Method) String() string {
	switch m {
	case MethodNone:
		return "none"
	case MethodRPK:
		return "rpk"
	case MethodPKIX:
		return "pkix"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
}

// SPKIHash is a SHA-256 hash of a DER-encoded SPKI
type SPKIHash = [32]byte

// Signature contains the authenticator and signature data
type Signature struct {
	Authenticator []byte // SPKI for RPK, certificate chain for PKIX
	NotAfter      uint64 // Unix timestamp (0 for PKIX)
	Algorithm     uint16 // TLS SignatureScheme
	SignatureData []byte // The actual signature bytes
}

// Auth represents the ech_auth extension
type Auth struct {
	Method      Method
	TrustedKeys []SPKIHash
	Signature   *Signature
}

// Error types
var (
	ErrDecode             = errors.New("echauth: decode error")
	ErrSignatureInvalid   = errors.New("echauth: signature verification failed")
	ErrUntrustedKey       = errors.New("echauth: SPKI hash not in trusted_keys")
	ErrExpired            = errors.New("echauth: config expired")
	ErrUnsupportedMethod  = errors.New("echauth: unsupported method")
	ErrUnsupportedAlgo    = errors.New("echauth: unsupported algorithm")
	ErrSignatureMissing   = errors.New("echauth: signature block missing")
	ErrInvalidSPKI        = errors.New("echauth: invalid SPKI format")
)

// Ed25519 SPKI prefix (DER encoding)
// 30 2a 30 05 06 03 2b 65 70 03 21 00 <32 bytes key>
var ed25519SPKIPrefix = []byte{
	0x30, 0x2a, // SEQUENCE (42 bytes)
	0x30, 0x05, // SEQUENCE (5 bytes)
	0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
	0x03, 0x21, 0x00, // BIT STRING (33 bytes, 0 unused)
}

// EncodeEd25519SPKI encodes an Ed25519 public key as DER SPKI
func EncodeEd25519SPKI(publicKey []byte) []byte {
	if len(publicKey) != 32 {
		return nil
	}
	spki := make([]byte, 44)
	copy(spki, ed25519SPKIPrefix)
	copy(spki[12:], publicKey)
	return spki
}

// ExtractEd25519PublicKey extracts the public key from an Ed25519 SPKI
func ExtractEd25519PublicKey(spki []byte) ([]byte, error) {
	if len(spki) != 44 {
		return nil, fmt.Errorf("%w: expected 44 bytes, got %d", ErrInvalidSPKI, len(spki))
	}
	// Validate prefix
	for i := 0; i < 12; i++ {
		if spki[i] != ed25519SPKIPrefix[i] {
			return nil, fmt.Errorf("%w: SPKI prefix does not match Ed25519 OID", ErrInvalidSPKI)
		}
	}
	return spki[12:44], nil
}

// ComputeSPKIHash computes SHA-256 hash of SPKI
func ComputeSPKIHash(spki []byte) SPKIHash {
	return sha256.Sum256(spki)
}

// SignRPK signs an ECHConfig with RPK method using Ed25519
func SignRPK(echConfigTBS []byte, privateKey ed25519.PrivateKey, notAfter time.Time) *Signature {
	// Extract public key and encode as SPKI
	publicKey := privateKey.Public().(ed25519.PublicKey)
	spki := EncodeEd25519SPKI(publicKey)

	// Build to_be_signed = context_label || ech_config_tbs
	toSign := make([]byte, len(ContextLabel)+len(echConfigTBS))
	copy(toSign, ContextLabel)
	copy(toSign[len(ContextLabel):], echConfigTBS)

	// Sign
	sig := ed25519.Sign(privateKey, toSign)

	return &Signature{
		Authenticator: spki,
		NotAfter:      uint64(notAfter.Unix()),
		Algorithm:     Ed25519SignatureScheme,
		SignatureData: sig,
	}
}

// VerifyRPK verifies an ECHAuth extension with RPK method
func VerifyRPK(echConfigTBS []byte, auth *Auth, now time.Time) error {
	// Step 1: Check method
	if auth.Method != MethodRPK {
		return fmt.Errorf("%w: %d", ErrUnsupportedMethod, auth.Method)
	}

	// Step 2: Check signature exists
	if auth.Signature == nil {
		return ErrSignatureMissing
	}
	sig := auth.Signature

	// Step 3: Check algorithm
	if sig.Algorithm != Ed25519SignatureScheme {
		return fmt.Errorf("%w: 0x%04x", ErrUnsupportedAlgo, sig.Algorithm)
	}

	// Step 4: Extract and validate public key
	publicKeyBytes, err := ExtractEd25519PublicKey(sig.Authenticator)
	if err != nil {
		return err
	}

	// Step 5: Compute SPKI hash and check membership
	spkiHash := ComputeSPKIHash(sig.Authenticator)
	found := false
	for _, trusted := range auth.TrustedKeys {
		if spkiHash == trusted {
			found = true
			break
		}
	}
	if !found {
		return ErrUntrustedKey
	}

	// Step 6: Check expiration
	if uint64(now.Unix()) >= sig.NotAfter {
		return fmt.Errorf("%w: not_after %d < current %d", ErrExpired, sig.NotAfter, now.Unix())
	}

	// Step 7: Build to_be_signed and verify
	toSign := make([]byte, len(ContextLabel)+len(echConfigTBS))
	copy(toSign, ContextLabel)
	copy(toSign[len(ContextLabel):], echConfigTBS)

	if len(sig.SignatureData) != ed25519.SignatureSize {
		return ErrSignatureInvalid
	}

	if !ed25519.Verify(publicKeyBytes, toSign, sig.SignatureData) {
		return ErrSignatureInvalid
	}

	return nil
}

// Encode serializes Auth to TLS wire format
func (a *Auth) Encode() []byte {
	// Calculate size
	size := 1 // method
	size += 2 // trusted_keys length
	size += len(a.TrustedKeys) * 32

	// Signature block (no outer length prefix per TLS presentation language)
	if a.Signature != nil {
		size += 2 + len(a.Signature.Authenticator) // authenticator
		size += 8                                   // not_after
		size += 2                                   // algorithm
		size += 2 + len(a.Signature.SignatureData)  // signature
	}

	buf := make([]byte, size)
	offset := 0

	// Method
	buf[offset] = byte(a.Method)
	offset++

	// Trusted keys
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(a.TrustedKeys)*32))
	offset += 2
	for _, key := range a.TrustedKeys {
		copy(buf[offset:], key[:])
		offset += 32
	}

	// Signature block (directly written, no outer length prefix)
	if a.Signature != nil {
		// Authenticator
		binary.BigEndian.PutUint16(buf[offset:], uint16(len(a.Signature.Authenticator)))
		offset += 2
		copy(buf[offset:], a.Signature.Authenticator)
		offset += len(a.Signature.Authenticator)

		// NotAfter
		binary.BigEndian.PutUint64(buf[offset:], a.Signature.NotAfter)
		offset += 8

		// Algorithm
		binary.BigEndian.PutUint16(buf[offset:], a.Signature.Algorithm)
		offset += 2

		// Signature data
		binary.BigEndian.PutUint16(buf[offset:], uint16(len(a.Signature.SignatureData)))
		offset += 2
		copy(buf[offset:], a.Signature.SignatureData)
	}

	return buf
}

// Decode parses Auth from TLS wire format
func Decode(data []byte) (*Auth, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("%w: insufficient data", ErrDecode)
	}

	offset := 0
	auth := &Auth{}

	// Method
	auth.Method = Method(data[offset])
	offset++

	// Trusted keys
	if len(data) < offset+2 {
		return nil, fmt.Errorf("%w: insufficient data for trusted_keys length", ErrDecode)
	}
	keysLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	if keysLen%32 != 0 {
		return nil, fmt.Errorf("%w: trusted_keys length not multiple of 32", ErrDecode)
	}
	if len(data) < offset+keysLen {
		return nil, fmt.Errorf("%w: insufficient data for trusted_keys", ErrDecode)
	}

	numKeys := keysLen / 32
	auth.TrustedKeys = make([]SPKIHash, numKeys)
	for i := 0; i < numKeys; i++ {
		copy(auth.TrustedKeys[i][:], data[offset:offset+32])
		offset += 32
	}

	// Signature block (only present when method != none)
	if auth.Method == MethodNone {
		return auth, nil
	}

	// No more data means no signature (for method=none compatibility)
	if offset >= len(data) {
		return auth, nil
	}

	sig := &Signature{}

	// Authenticator
	if len(data) < offset+2 {
		return nil, fmt.Errorf("%w: insufficient data for authenticator length", ErrDecode)
	}
	authLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	if len(data) < offset+authLen {
		return nil, fmt.Errorf("%w: insufficient data for authenticator", ErrDecode)
	}
	sig.Authenticator = make([]byte, authLen)
	copy(sig.Authenticator, data[offset:offset+authLen])
	offset += authLen

	// NotAfter
	if len(data) < offset+8 {
		return nil, fmt.Errorf("%w: insufficient data for not_after", ErrDecode)
	}
	sig.NotAfter = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Algorithm
	if len(data) < offset+2 {
		return nil, fmt.Errorf("%w: insufficient data for algorithm", ErrDecode)
	}
	sig.Algorithm = binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// Signature data
	if len(data) < offset+2 {
		return nil, fmt.Errorf("%w: insufficient data for signature length", ErrDecode)
	}
	sigDataLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	if len(data) < offset+sigDataLen {
		return nil, fmt.Errorf("%w: insufficient data for signature data", ErrDecode)
	}
	sig.SignatureData = make([]byte, sigDataLen)
	copy(sig.SignatureData, data[offset:offset+sigDataLen])

	auth.Signature = sig
	return auth, nil
}
