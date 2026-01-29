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

// SpecVersion identifies the wire format version
type SpecVersion uint8

const (
	// SpecPR2 is the PR #2 format: rpk=0, pkix=1, not_after required for PKIX
	SpecPR2 SpecVersion = iota
	// SpecPublished is the -00 draft: none=0, rpk=1, pkix=2, not_after=0 for PKIX
	SpecPublished
)

// DefaultSpecVersion is used by non-versioned APIs.
// Change this to switch the entire library's wire format.
var DefaultSpecVersion = SpecPR2

// Method identifies the authentication method
type Method uint8

const (
	MethodRPK  Method = 0
	MethodPKIX Method = 1
)

func (m Method) String() string {
	switch m {
	case MethodRPK:
		return "rpk"
	case MethodPKIX:
		return "pkix"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
}

// ToWire converts Method to wire format byte using spec version
func (m Method) ToWire(ver SpecVersion) uint8 {
	switch ver {
	case SpecPR2:
		// PR2: rpk=0, pkix=1
		return uint8(m)
	case SpecPublished:
		// Published: rpk=1, pkix=2
		return uint8(m) + 1
	default:
		return uint8(m)
	}
}

// MethodFromWire parses Method from wire format byte using spec version
func MethodFromWire(val uint8, ver SpecVersion) (Method, error) {
	switch ver {
	case SpecPR2:
		// PR2: rpk=0, pkix=1
		if val > 1 {
			return 0, fmt.Errorf("%w: %d", ErrUnsupportedMethod, val)
		}
		return Method(val), nil
	case SpecPublished:
		// Published: none=0 (unsupported), rpk=1, pkix=2
		if val == 0 {
			return 0, fmt.Errorf("%w: 'none' method not supported", ErrUnsupportedMethod)
		}
		if val > 2 {
			return 0, fmt.Errorf("%w: %d", ErrUnsupportedMethod, val)
		}
		return Method(val - 1), nil
	default:
		return 0, fmt.Errorf("%w: unknown version", ErrDecode)
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

// EncodeVersioned serializes Auth to TLS wire format with spec version
func (a *Auth) EncodeVersioned(ver SpecVersion) []byte {
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

	// Method (version-aware)
	buf[offset] = a.Method.ToWire(ver)
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

// Encode serializes Auth to TLS wire format (uses DefaultSpecVersion)
func (a *Auth) Encode() []byte {
	return a.EncodeVersioned(DefaultSpecVersion)
}

// DecodeVersioned parses Auth from TLS wire format with spec version
func DecodeVersioned(data []byte, ver SpecVersion) (*Auth, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("%w: insufficient data", ErrDecode)
	}

	offset := 0
	auth := &Auth{}

	// Method (version-aware)
	method, err := MethodFromWire(data[offset], ver)
	if err != nil {
		return nil, err
	}
	auth.Method = method
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

	// No more data means no signature
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

// Decode parses Auth from TLS wire format (uses DefaultSpecVersion)
func Decode(data []byte) (*Auth, error) {
	return DecodeVersioned(data, DefaultSpecVersion)
}

// DetectVersion heuristically detects the spec version from encoded data.
// Returns (version, ok) where ok is false if detection is ambiguous or data invalid.
//
// Detection logic:
// - method=2: definitely Published (pkix)
// - method=0: likely PR2 (rpk) but could be Published 'none'
// - method=1: ambiguous (PR2 pkix vs Published rpk)
func DetectVersion(data []byte) (SpecVersion, bool) {
	if len(data) == 0 {
		return 0, false
	}

	switch data[0] {
	case 0:
		return SpecPR2, true    // PR2 rpk (Published 'none' not supported)
	case 1:
		return 0, false         // Ambiguous: PR2 pkix OR Published rpk
	case 2:
		return SpecPublished, true // Definitely Published pkix
	default:
		return 0, false         // Invalid method
	}
}

// ============================================================================
// PR #2 Split Structures
// ============================================================================

// AuthInfo is the ech_authinfo extension for DNS HTTPS records (PR #2 format)
// Contains only policy (method + trusted keys), no signature
type AuthInfo struct {
	Method      Method
	TrustedKeys []SPKIHash
}

// AuthRetry is the ech_auth extension for TLS retry configs (PR #2 format)
// Contains the full signature material
type AuthRetry struct {
	Method        Method
	NotAfter      uint64
	Authenticator []byte
	Algorithm     uint16
	Signature     []byte
}

// EncodeVersioned serializes AuthInfo to wire format
func (a *AuthInfo) EncodeVersioned(ver SpecVersion) []byte {
	size := 1 + 2 + len(a.TrustedKeys)*32
	buf := make([]byte, size)
	offset := 0

	buf[offset] = a.Method.ToWire(ver)
	offset++

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(a.TrustedKeys)*32))
	offset += 2

	for _, key := range a.TrustedKeys {
		copy(buf[offset:], key[:])
		offset += 32
	}

	return buf
}

// Encode serializes AuthInfo (uses DefaultSpecVersion)
func (a *AuthInfo) Encode() []byte {
	return a.EncodeVersioned(DefaultSpecVersion)
}

// DecodeAuthInfoVersioned parses AuthInfo from wire format
func DecodeAuthInfoVersioned(data []byte, ver SpecVersion) (*AuthInfo, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("%w: insufficient data", ErrDecode)
	}

	method, err := MethodFromWire(data[0], ver)
	if err != nil {
		return nil, err
	}

	keysLen := int(binary.BigEndian.Uint16(data[1:3]))
	if keysLen%32 != 0 {
		return nil, fmt.Errorf("%w: trusted_keys length not multiple of 32", ErrDecode)
	}
	if len(data) < 3+keysLen {
		return nil, fmt.Errorf("%w: insufficient data for trusted_keys", ErrDecode)
	}

	numKeys := keysLen / 32
	trustedKeys := make([]SPKIHash, numKeys)
	for i := 0; i < numKeys; i++ {
		copy(trustedKeys[i][:], data[3+i*32:3+(i+1)*32])
	}

	return &AuthInfo{Method: method, TrustedKeys: trustedKeys}, nil
}

// DecodeAuthInfo parses AuthInfo (uses DefaultSpecVersion)
func DecodeAuthInfo(data []byte) (*AuthInfo, error) {
	return DecodeAuthInfoVersioned(data, DefaultSpecVersion)
}

// EncodeVersioned serializes AuthRetry to wire format
func (a *AuthRetry) EncodeVersioned(ver SpecVersion) []byte {
	size := 1 + 8 + 2 + len(a.Authenticator) + 2 + 2 + len(a.Signature)
	buf := make([]byte, size)
	offset := 0

	buf[offset] = a.Method.ToWire(ver)
	offset++

	binary.BigEndian.PutUint64(buf[offset:], a.NotAfter)
	offset += 8

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(a.Authenticator)))
	offset += 2
	copy(buf[offset:], a.Authenticator)
	offset += len(a.Authenticator)

	binary.BigEndian.PutUint16(buf[offset:], a.Algorithm)
	offset += 2

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(a.Signature)))
	offset += 2
	copy(buf[offset:], a.Signature)

	return buf
}

// Encode serializes AuthRetry (uses DefaultSpecVersion)
func (a *AuthRetry) Encode() []byte {
	return a.EncodeVersioned(DefaultSpecVersion)
}

// DecodeAuthRetryVersioned parses AuthRetry from wire format
func DecodeAuthRetryVersioned(data []byte, ver SpecVersion) (*AuthRetry, error) {
	if len(data) < 11 {
		return nil, fmt.Errorf("%w: insufficient data", ErrDecode)
	}

	offset := 0
	method, err := MethodFromWire(data[offset], ver)
	if err != nil {
		return nil, err
	}
	offset++

	notAfter := binary.BigEndian.Uint64(data[offset:])
	offset += 8

	authLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if len(data) < offset+authLen {
		return nil, fmt.Errorf("%w: insufficient data for authenticator", ErrDecode)
	}
	authenticator := make([]byte, authLen)
	copy(authenticator, data[offset:offset+authLen])
	offset += authLen

	if len(data) < offset+2 {
		return nil, fmt.Errorf("%w: insufficient data for algorithm", ErrDecode)
	}
	algorithm := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	if len(data) < offset+2 {
		return nil, fmt.Errorf("%w: insufficient data for signature length", ErrDecode)
	}
	sigLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if len(data) < offset+sigLen {
		return nil, fmt.Errorf("%w: insufficient data for signature", ErrDecode)
	}
	signature := make([]byte, sigLen)
	copy(signature, data[offset:offset+sigLen])

	return &AuthRetry{
		Method:        method,
		NotAfter:      notAfter,
		Authenticator: authenticator,
		Algorithm:     algorithm,
		Signature:     signature,
	}, nil
}

// DecodeAuthRetry parses AuthRetry (uses DefaultSpecVersion)
func DecodeAuthRetry(data []byte) (*AuthRetry, error) {
	return DecodeAuthRetryVersioned(data, DefaultSpecVersion)
}

// SPKIHash computes the SHA-256 hash of the authenticator (for RPK verification)
func (a *AuthRetry) SPKIHash() SPKIHash {
	return sha256.Sum256(a.Authenticator)
}

// ToSplitFormat converts Auth to PR #2 split format (AuthInfo + AuthRetry)
func (a *Auth) ToSplitFormat() (*AuthInfo, *AuthRetry) {
	info := &AuthInfo{
		Method:      a.Method,
		TrustedKeys: a.TrustedKeys,
	}

	var retry *AuthRetry
	if a.Signature != nil {
		retry = &AuthRetry{
			Method:        a.Method,
			NotAfter:      a.Signature.NotAfter,
			Authenticator: a.Signature.Authenticator,
			Algorithm:     a.Signature.Algorithm,
			Signature:     a.Signature.SignatureData,
		}
	}

	return info, retry
}
