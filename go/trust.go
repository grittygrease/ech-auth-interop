// trust.go - Client-side trust model for ECH authentication
package echauth

import (
	"fmt"
	"time"
)

// TrustSource indicates where the trust anchor came from
type TrustSource int

const (
	// TrustSourceNone - No trust anchor available
	TrustSourceNone TrustSource = iota
	// TrustSourceDNS - Trust anchor from DNS HTTPS record
	TrustSourceDNS
	// TrustSourceRetry - Trust anchor from TLS retry_config (bootstrapped)
	TrustSourceRetry
)

func (ts TrustSource) String() string {
	switch ts {
	case TrustSourceNone:
		return "none"
	case TrustSourceDNS:
		return "dns"
	case TrustSourceRetry:
		return "retry"
	default:
		return "unknown"
	}
}

// TrustDecision is the result of trust evaluation
type TrustDecision int

const (
	// TrustDecisionAccept - Use the config for ECH
	TrustDecisionAccept TrustDecision = iota
	// TrustDecisionGREASE - Don't use ECH, send GREASE instead
	TrustDecisionGREASE
	// TrustDecisionReject - Reject the config, verification failed
	TrustDecisionReject
)

func (td TrustDecision) String() string {
	switch td {
	case TrustDecisionAccept:
		return "accept"
	case TrustDecisionGREASE:
		return "grease"
	case TrustDecisionReject:
		return "reject"
	default:
		return "unknown"
	}
}

// CachedConfig represents a cached ECH configuration with trust metadata
type CachedConfig struct {
	PublicName  string
	Config      *ECHConfig
	Auth        *Auth
	TrustSource TrustSource
	CachedAt    time.Time

	// For RPK: the SPKI hash from DNS
	RPKTrustAnchor *SPKIHash

	// For PKIX: the root certificate
	PKIXTrustAnchor *PKIXTrustAnchor
}

// ConfigCache manages cached ECH configurations indexed by public_name
type ConfigCache struct {
	configs map[string]*CachedConfig
}

// NewConfigCache creates a new empty config cache
func NewConfigCache() *ConfigCache {
	return &ConfigCache{
		configs: make(map[string]*CachedConfig),
	}
}

// Get retrieves a cached config by public_name
func (c *ConfigCache) Get(publicName string) (*CachedConfig, bool) {
	cfg, ok := c.configs[publicName]
	return cfg, ok
}

// Put stores a config in the cache
func (c *ConfigCache) Put(cfg *CachedConfig) {
	c.configs[cfg.PublicName] = cfg
}

// EvaluateTrustInput contains all inputs needed for trust evaluation
type EvaluateTrustInput struct {
	// The ECH config received (from DNS or retry_config)
	Config *ECHConfig

	// The Auth extension parsed from the config
	Auth *Auth

	// Whether this config came from DNS (vs TLS retry)
	FromDNS bool

	// Whether DNS confirms ECH support for this domain
	DNSConfirmsECH bool

	// For RPK: SPKI hash from DNS HTTPS record (nil if not available)
	DNSRPKAnchor *SPKIHash

	// For PKIX: root certificate pool (nil to use system roots)
	PKIXRoots *PKIXTrustAnchor

	// Current time for expiration checks
	Now time.Time
}

// EvaluateTrustResult contains the decision and any error details
type EvaluateTrustResult struct {
	Decision TrustDecision
	Reason   string
	Error    error

	// If Accept, the validated config ready to cache
	ValidatedConfig *CachedConfig
}

// EvaluateTrust determines whether to accept, GREASE, or reject an ECH config
func EvaluateTrust(input *EvaluateTrustInput) *EvaluateTrustResult {
	// No auth extension = unsigned config
	if input.Auth == nil {
		// If we have a cached signed config, reject unsigned downgrade
		// Otherwise, treat as legacy unsigned config
		return &EvaluateTrustResult{
			Decision: TrustDecisionGREASE,
			Reason:   "config has no ech_auth extension",
		}
	}

	// Check method
	switch input.Auth.Method {
	case MethodRPK:
		return evaluateTrustRPK(input)
	case MethodPKIX:
		return evaluateTrustPKIX(input)
	default:
		return &EvaluateTrustResult{
			Decision: TrustDecisionReject,
			Reason:   fmt.Sprintf("unknown auth method: %d", input.Auth.Method),
		}
	}
}

// evaluateTrustRPK handles RPK method trust evaluation
func evaluateTrustRPK(input *EvaluateTrustInput) *EvaluateTrustResult {
	// RPK requires pre-provisioned trust anchor from DNS
	if input.DNSRPKAnchor == nil {
		// No DNS trust anchor = cannot verify RPK
		if input.FromDNS {
			// This shouldn't happen - DNS should provide the anchor
			return &EvaluateTrustResult{
				Decision: TrustDecisionReject,
				Reason:   "RPK from DNS but no SPKI hash in HTTPS record",
			}
		}
		// Retry config with RPK but no DNS anchor = GREASE
		return &EvaluateTrustResult{
			Decision: TrustDecisionGREASE,
			Reason:   "RPK retry config but no DNS trust anchor",
		}
	}

	// Compute TBS for verification
	tbs, err := input.Config.ComputeTBS()
	if err != nil {
		return &EvaluateTrustResult{
			Decision: TrustDecisionReject,
			Reason:   "failed to compute TBS",
			Error:    err,
		}
	}

	// Verify signature against DNS trust anchor
	err = VerifyRPKWithAnchor(tbs, input.Auth, *input.DNSRPKAnchor, input.Now)
	if err != nil {
		return &EvaluateTrustResult{
			Decision: TrustDecisionReject,
			Reason:   fmt.Sprintf("RPK verification failed: %v", err),
			Error:    err,
		}
	}

	// Verified! Determine trust source
	source := TrustSourceRetry
	if input.FromDNS {
		source = TrustSourceDNS
	}

	// Inject anchor into Auth so VerifyRPK passes (it checks TrustedKeys)
	input.Auth.TrustedKeys = []SPKIHash{*input.DNSRPKAnchor}

	return &EvaluateTrustResult{
		Decision: TrustDecisionAccept,
		Reason:   "RPK signature verified against DNS anchor",
		ValidatedConfig: &CachedConfig{
			PublicName:     string(input.Config.PublicName),
			Config:         input.Config,
			Auth:           input.Auth,
			TrustSource:    source,
			RPKTrustAnchor: input.DNSRPKAnchor,
			CachedAt:       input.Now,
		},
	}
}

// evaluateTrustPKIX handles PKIX method trust evaluation
func evaluateTrustPKIX(input *EvaluateTrustInput) *EvaluateTrustResult {
	// Compute TBS for verification
	tbs, err := input.Config.ComputeTBS()
	if err != nil {
		return &EvaluateTrustResult{
			Decision: TrustDecisionReject,
			Reason:   "failed to compute TBS",
			Error:    err,
		}
	}

	// Verify PKIX signature
	publicName := string(input.Config.PublicName)
	err = VerifyPKIX(tbs, input.Auth, publicName, input.PKIXRoots, input.Now)
	if err != nil {
		return &EvaluateTrustResult{
			Decision: TrustDecisionReject,
			Reason:   fmt.Sprintf("PKIX verification failed: %v", err),
			Error:    err,
		}
	}

	// PKIX verified! But what's the trust decision?
	source := TrustSourceRetry
	if input.FromDNS {
		source = TrustSourceDNS
	}

	validatedConfig := &CachedConfig{
		PublicName:      publicName,
		Config:          input.Config,
		Auth:            input.Auth,
		TrustSource:     source,
		PKIXTrustAnchor: input.PKIXRoots,
		CachedAt:        input.Now,
	}

	// If DNS confirms ECH support, accept
	if input.DNSConfirmsECH {
		return &EvaluateTrustResult{
			Decision:        TrustDecisionAccept,
			Reason:          "PKIX verified and DNS confirms ECH",
			ValidatedConfig: validatedConfig,
		}
	}

	// PKIX verified but DNS doesn't confirm ECH
	// Cache the config but GREASE until DNS confirms
	return &EvaluateTrustResult{
		Decision:        TrustDecisionGREASE,
		Reason:          "PKIX verified but DNS does not confirm ECH (cache and GREASE)",
		ValidatedConfig: validatedConfig, // Still cache it
	}
}

// VerifyRPKWithAnchor verifies RPK signature against a specific SPKI hash anchor
func VerifyRPKWithAnchor(echConfigTBS []byte, auth *Auth, anchor SPKIHash, now time.Time) error {
	// Check method
	if auth.Method != MethodRPK {
		return fmt.Errorf("%w: expected RPK, got %v", ErrUnsupportedMethod, auth.Method)
	}

	// Check signature exists
	if auth.Signature == nil {
		return ErrSignatureMissing
	}
	sig := auth.Signature

	// Check expiration
	if uint64(now.Unix()) >= sig.NotAfter {
		return fmt.Errorf("%w: not_after %d < current %d", ErrExpired, sig.NotAfter, now.Unix())
	}

	// Compute SPKI hash of authenticator
	spkiHash := ComputeSPKIHash(sig.Authenticator)

	// Check against anchor
	if spkiHash != anchor {
		return ErrUntrustedKey
	}

	// Verify signature
	_, err := ExtractEd25519PublicKey(sig.Authenticator)
	if err != nil {
		return ErrSignatureInvalid
	}

	// Actually verify
	// Inject anchor into Auth so VerifyRPK passes (it checks TrustedKeys)
	auth.TrustedKeys = []SPKIHash{anchor}
	return VerifyRPK(echConfigTBS, auth, now)
}

// Helper to check if cache has a signed config for downgrade detection
func (c *ConfigCache) HasSignedConfig(publicName string) bool {
	cfg, ok := c.configs[publicName]
	if !ok {
		return false
	}
	return cfg.Auth != nil
}

// ShouldRejectDowngrade checks if accepting unsigned config would be a downgrade
func (c *ConfigCache) ShouldRejectDowngrade(publicName string, newAuth *Auth) bool {
	cached, ok := c.configs[publicName]
	if !ok {
		return false // No cached config, not a downgrade
	}

	// Had signed, receiving unsigned = downgrade
	if cached.Auth != nil && newAuth == nil {
		return true
	}

	return false
}
