// ECHConfig and ECHConfigList parsing for crypto/tls integration

package echauth

import (
	"encoding/binary"
	"fmt"
	"time"
)

// ECHConfig version for draft-ietf-tls-esni
const ECHConfigVersion uint16 = 0xfe0d

// ECHConfig represents a parsed ECH configuration
type ECHConfig struct {
	Version    uint16
	Length     uint16
	ConfigID   uint8
	KemID      uint16
	PublicKey  []byte
	Ciphers    []CipherSuite
	MaxNameLen uint8
	PublicName []byte
	Extensions []Extension
	Raw        []byte // Original bytes for TBS computation
}

// CipherSuite is a KDF/AEAD pair
type CipherSuite struct {
	KdfID  uint16
	AeadID uint16
}

// Extension is a generic TLS extension
type Extension struct {
	Type uint16
	Data []byte
}

// ECHConfigList parsing errors
var (
	ErrConfigListEmpty     = fmt.Errorf("%w: empty config list", ErrDecode)
	ErrConfigListTruncated = fmt.Errorf("%w: config list truncated", ErrDecode)
	ErrConfigTruncated     = fmt.Errorf("%w: config truncated", ErrDecode)
	ErrConfigVersion       = fmt.Errorf("%w: unsupported config version", ErrDecode)
	ErrNoAuthExtension     = fmt.Errorf("%w: no ech_auth extension found", ErrDecode)
)

// ParseECHConfigList parses a serialized ECHConfigList
func ParseECHConfigList(data []byte) ([]ECHConfig, error) {
	if len(data) < 2 {
		return nil, ErrConfigListEmpty
	}

	listLen := int(binary.BigEndian.Uint16(data[:2]))
	if len(data) < 2+listLen {
		return nil, ErrConfigListTruncated
	}

	var configs []ECHConfig
	offset := 2
	end := 2 + listLen

	for offset < end {
		config, consumed, err := parseECHConfig(data[offset:end])
		if err != nil {
			return nil, err
		}
		configs = append(configs, config)
		offset += consumed
	}

	return configs, nil
}

// parseECHConfig parses a single ECHConfig, returns config and bytes consumed
func parseECHConfig(data []byte) (ECHConfig, int, error) {
	if len(data) < 4 {
		return ECHConfig{}, 0, ErrConfigTruncated
	}

	config := ECHConfig{}
	config.Version = binary.BigEndian.Uint16(data[0:2])
	config.Length = binary.BigEndian.Uint16(data[2:4])

	totalLen := 4 + int(config.Length)
	if len(data) < totalLen {
		return ECHConfig{}, 0, ErrConfigTruncated
	}

	// Store raw bytes for TBS computation
	config.Raw = make([]byte, totalLen)
	copy(config.Raw, data[:totalLen])

	// Only parse contents if version matches
	if config.Version != ECHConfigVersion {
		// Skip unknown versions per spec
		return config, totalLen, nil
	}

	offset := 4

	// ConfigID (1 byte)
	if offset >= len(data) {
		return ECHConfig{}, 0, ErrConfigTruncated
	}
	config.ConfigID = data[offset]
	offset++

	// KEM ID (2 bytes)
	if offset+2 > len(data) {
		return ECHConfig{}, 0, ErrConfigTruncated
	}
	config.KemID = binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// Public key (length-prefixed)
	if offset+2 > len(data) {
		return ECHConfig{}, 0, ErrConfigTruncated
	}
	pkLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+pkLen > len(data) {
		return ECHConfig{}, 0, ErrConfigTruncated
	}
	config.PublicKey = make([]byte, pkLen)
	copy(config.PublicKey, data[offset:offset+pkLen])
	offset += pkLen

	// Cipher suites (length-prefixed)
	if offset+2 > len(data) {
		return ECHConfig{}, 0, ErrConfigTruncated
	}
	ciphersLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if ciphersLen%4 != 0 {
		return ECHConfig{}, 0, fmt.Errorf("%w: cipher suites length not multiple of 4", ErrDecode)
	}
	if offset+ciphersLen > len(data) {
		return ECHConfig{}, 0, ErrConfigTruncated
	}
	numCiphers := ciphersLen / 4
	config.Ciphers = make([]CipherSuite, numCiphers)
	for i := 0; i < numCiphers; i++ {
		config.Ciphers[i].KdfID = binary.BigEndian.Uint16(data[offset:])
		config.Ciphers[i].AeadID = binary.BigEndian.Uint16(data[offset+2:])
		offset += 4
	}

	// Maximum name length (1 byte)
	if offset >= len(data) {
		return ECHConfig{}, 0, ErrConfigTruncated
	}
	config.MaxNameLen = data[offset]
	offset++

	// Public name (length-prefixed, 1-byte length)
	if offset >= len(data) {
		return ECHConfig{}, 0, ErrConfigTruncated
	}
	nameLen := int(data[offset])
	offset++
	if offset+nameLen > len(data) {
		return ECHConfig{}, 0, ErrConfigTruncated
	}
	config.PublicName = make([]byte, nameLen)
	copy(config.PublicName, data[offset:offset+nameLen])
	offset += nameLen

	// Extensions (length-prefixed)
	if offset+2 > len(data) {
		return ECHConfig{}, 0, ErrConfigTruncated
	}
	extLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	extEnd := offset + extLen
	if extEnd > len(data) {
		return ECHConfig{}, 0, ErrConfigTruncated
	}

	var echAuthSeen bool
	for offset < extEnd {
		if offset+4 > extEnd {
			return ECHConfig{}, 0, ErrConfigTruncated
		}
		ext := Extension{
			Type: binary.BigEndian.Uint16(data[offset:]),
		}
		offset += 2
		extDataLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if offset+extDataLen > extEnd {
			return ECHConfig{}, 0, ErrConfigTruncated
		}
		ext.Data = make([]byte, extDataLen)
		copy(ext.Data, data[offset:offset+extDataLen])
		offset += extDataLen

		// COMPLIANCE: Section 5.1 - ech_auth MUST be last extension if present
		if echAuthSeen {
			return ECHConfig{}, 0, fmt.Errorf("%w: ech_auth extension must be last (found extension 0x%04x after ech_auth)", ErrDecode, ext.Type)
		}
		if ext.Type == ECHAuthExtensionType {
			echAuthSeen = true
		}

		config.Extensions = append(config.Extensions, ext)
	}

	return config, totalLen, nil
}

// GetAuthExtension extracts the ech_auth extension from an ECHConfig
func (c *ECHConfig) GetAuthExtension() (*Auth, error) {
	for _, ext := range c.Extensions {
		if ext.Type == ECHAuthExtensionType {
			return Decode(ext.Data)
		}
	}
	return nil, ErrNoAuthExtension
}

// Clone creates a deep copy of the ECHConfig
func (c *ECHConfig) Clone() ECHConfig {
	out := *c
	if c.PublicKey != nil {
		out.PublicKey = append([]byte(nil), c.PublicKey...)
	}
	if c.Ciphers != nil {
		out.Ciphers = append([]CipherSuite(nil), c.Ciphers...)
	}
	if c.PublicName != nil {
		out.PublicName = append([]byte(nil), c.PublicName...)
	}
	if c.Extensions != nil {
		out.Extensions = make([]Extension, len(c.Extensions))
		for i, ext := range c.Extensions {
			out.Extensions[i] = Extension{
				Type: ext.Type,
				Data: append([]byte(nil), ext.Data...),
			}
		}
	}
	out.Raw = nil // Invalidated by mutation
	return out
}

// Encode serializes ECHConfig to bytes
func (c *ECHConfig) Encode() []byte {
	w := NewWriter()
	w.PutUint16(c.Version)

	// Placeholder for length (filled later)
	lenOffset := len(w.Bytes())
	w.PutUint16(0)

	startOffset := len(w.Bytes())

	w.PutUint8(c.ConfigID)
	w.PutUint16(c.KemID)
	w.PutVector16(c.PublicKey)

	// Cipher Suites
	w.PutUint16(uint16(len(c.Ciphers) * 4))
	for _, cs := range c.Ciphers {
		w.PutUint16(cs.KdfID)
		w.PutUint16(cs.AeadID)
	}

	w.PutUint8(c.MaxNameLen)
	w.PutVector8(c.PublicName)

	// Extensions
	extW := NewWriter()
	for _, ext := range c.Extensions {
		extW.PutUint16(ext.Type)
		extW.PutVector16(ext.Data)
	}
	w.PutVector16(extW.Bytes())

	// Patch in length
	totalLen := len(w.Bytes()) - startOffset
	binary.BigEndian.PutUint16(w.Bytes()[lenOffset:], uint16(totalLen))

	return w.Bytes()
}

// ComputeTBS computes the to-be-signed bytes for an ECHConfig.
// This is done by creating a clone, zeroing the signature in the auth extension, and re-encoding.
func (c *ECHConfig) ComputeTBS() ([]byte, error) {
	clone := c.Clone()

	// Find the auth extension
	var authExt *Extension
	for i := range clone.Extensions {
		if clone.Extensions[i].Type == ECHAuthExtensionType {
			authExt = &clone.Extensions[i]
			break
		}
	}

	if authExt == nil {
		return nil, ErrNoAuthExtension
	}

	// Detect version to handle PR2 vs Legacy correctly
	ver, ok := DetectVersion(authExt.Data)
	if !ok {
		ver = DefaultSpecVersion
	}

	// Try interpreting as AuthRetry (contains signature) - mainly for PR2
	if ver == SpecPR2 {
		retry, err := DecodeAuthRetryVersioned(authExt.Data, ver)
		if err == nil {
			// Zero the signature
			retry.Signature = make([]byte, len(retry.Signature))
			for i := range retry.Signature {
				retry.Signature[i] = 0
			}
			// Write back
			authExt.Data = retry.EncodeVersioned(ver)
			return clone.Encode(), nil
		}
	}

	// Fallback/Legacy logic (Combined Auth)
	// Or if DecodeAuthRetry failed (though it shouldn't for PR2)
	auth, err := DecodeVersioned(authExt.Data, ver)
	if err != nil {
		return nil, fmt.Errorf("failed to decode auth extension for zeroing: %w", err)
	}
	if auth.Signature != nil {
		// Zero signature bytes
		zeroSig := make([]byte, len(auth.Signature.SignatureData))
		auth.Signature.SignatureData = zeroSig
		authExt.Data = auth.EncodeVersioned(ver)
	}

	return clone.Encode(), nil
}

// TrustAnchor holds pinned trust information for verification
type TrustAnchor struct {
	// TrustedKeys is the set of SPKI hashes to accept
	TrustedKeys []SPKIHash
}

// VerifyConfig verifies a single ECHConfig against trust anchors
func VerifyConfig(config *ECHConfig, anchor *TrustAnchor, now func() uint64) error {
	if config.Version != ECHConfigVersion {
		return fmt.Errorf("%w: 0x%04x", ErrConfigVersion, config.Version)
	}

	auth, err := config.GetAuthExtension()
	if err != nil {
		return err
	}

	// Inject trusted keys from anchor into auth for verification
	auth.TrustedKeys = anchor.TrustedKeys

	tbs, err := config.ComputeTBS()
	if err != nil {
		return err
	}

	switch auth.Method {
	case MethodRPK:
		return VerifyRPK(tbs, auth, timeFromUnix(now()))
	case MethodPKIX:
		return fmt.Errorf("%w: PKIX not yet implemented", ErrUnsupportedMethod)
	default:
		return fmt.Errorf("%w: %d", ErrUnsupportedMethod, auth.Method)
	}
}

// VerifyConfigList verifies an ECHConfigList from a TLS ECH rejection.
// Returns the list of verified configs, or error if none pass verification.
// If anchor is nil, returns all configs without verification (legacy mode).
func VerifyConfigList(data []byte, anchor *TrustAnchor, now func() uint64) ([]ECHConfig, error) {
	configs, err := ParseECHConfigList(data)
	if err != nil {
		return nil, err
	}

	if len(configs) == 0 {
		return nil, ErrConfigListEmpty
	}

	// Legacy mode: no verification when anchor is nil
	if anchor == nil {
		return configs, nil
	}

	// Empty trust anchors = fail-closed (reject all)
	if len(anchor.TrustedKeys) == 0 {
		return nil, ErrUntrustedKey
	}

	var verified []ECHConfig
	var lastErr error

	for _, config := range configs {
		if err := VerifyConfig(&config, anchor, now); err != nil {
			lastErr = err
			continue
		}
		verified = append(verified, config)
	}

	if len(verified) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, ErrSignatureInvalid
	}

	return verified, nil
}

// timeFromUnix converts unix timestamp to time.Time for VerifyRPK
func timeFromUnix(ts uint64) time.Time {
	return time.Unix(int64(ts), 0)
}
