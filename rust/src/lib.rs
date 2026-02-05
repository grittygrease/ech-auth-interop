//! ECH authentication library for draft-sullivan-tls-signed-ech-updates
//!
//! This library implements authenticated ECH configuration distribution,
//! allowing TLS clients to verify that ECH retry configs received during
//! handshake rejection come from the legitimate server operator.
//!
//! # Overview
//!
//! ECH (Encrypted Client Hello) authentication extends the ECH protocol with
//! cryptographic signatures to prevent downgrade attacks and ensure
//! configuration authenticity. This prevents attackers from forcing clients
//! to use outdated or malicious ECH configurations.
//!
//! # Architecture
//!
//! This library provides two API levels:
//!
//! ## Trust Model API (Recommended for TLS Clients)
//!
//! High-level API that handles trust decisions, DNS confirmation, and
//! downgrade protection:
//!
//! - [`evaluate_trust`] - Evaluate trust and return Accept/GREASE/Reject decision
//! - [`ConfigCache`] - Cache validated configs to prevent downgrades
//! - [`TrustDecision`] - The trust evaluation result
//! - [`EvaluateTrustInput`] - Input parameters for trust evaluation
//!
//! Use this API for production TLS clients. It implements the complete trust
//! model including DNS confirmation and protection against downgrade attacks.
//!
//! ## Low-Level Verification API
//!
//! Direct cryptographic verification without policy decisions:
//!
//! - [`verify_rpk`] - Verify RPK (Raw Public Key) signatures
//! - [`verify_pkix`] - Verify PKIX (Certificate Chain) signatures
//!
//! Use the low-level API only if you're implementing custom trust logic.
//! These functions perform pure cryptographic verification without checking
//! DNS confirmation or downgrade protection.
//!
//! # Authentication Methods
//!
//! ## RPK (Raw Public Key)
//!
//! Uses SPKI hash pinning similar to HPKP/DANE. The client pins SHA-256
//! hashes of trusted public keys and verifies signatures directly.
//!
//! Supported algorithms:
//! - Ed25519 (recommended for new deployments)
//! - ECDSA P-256 (secp256r1, for compatibility)
//!
//! **When to use RPK:**
//! - Simple deployments without PKI
//! - Direct key pinning requirements
//! - Avoiding certificate infrastructure
//!
//! ## PKIX (Certificate Chain)
//!
//! Uses X.509 certificate chains with WebPKI validation. Requires
//! certificates with the critical `id-pe-echConfigSigning` extension
//! (OID 1.3.6.1.5.5.7.1.99).
//!
//! **When to use PKIX:**
//! - Existing PKI infrastructure
//! - Certificate rotation via CA
//! - Enterprise environments
//!
//! # Examples
//!
//! ## Client: Trust Evaluation
//!
//! ```no_run
//! use ech_auth::*;
//! use std::time::{SystemTime, UNIX_EPOCH};
//!
//! # fn main() -> ech_auth::Result<()> {
//! // 1. Receive ECH config from DNS
//! # let dns_echconfig_bytes = &[0u8; 100];
//! let config = ECHConfig::decode(dns_echconfig_bytes)?;
//!
//! // 2. Extract ech_auth extension (if present)
//! let auth = config.extract_ech_auth()?;
//!
//! // 3. Evaluate trust with DNS-provided SPKI hash
//! # let pinned_spki_hash = [0u8; 32];
//! let current_time = SystemTime::now()
//!     .duration_since(UNIX_EPOCH)
//!     .unwrap()
//!     .as_secs();
//!
//! let result = evaluate_trust(&EvaluateTrustInput {
//!     config: &config,
//!     auth: auth.as_ref(),
//!     from_dns: true,
//!     dns_confirms_ech: true,
//!     dns_rpk_anchor: Some(pinned_spki_hash),
//!     pkix_roots: vec![],
//!     now: current_time,
//! });
//!
//! // 4. Act on decision
//! match result.decision {
//!     TrustDecision::Accept => {
//!         // Use the ECH config for your connection
//!         println!("ECH config accepted");
//!     }
//!     TrustDecision::GREASE => {
//!         // Send GREASE ECH instead (preserves privacy)
//!         println!("Sending GREASE ECH");
//!     }
//!     TrustDecision::Reject => {
//!         // Signature verification failed
//!         println!("ECH config rejected");
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Server: Signing Configs
//!
//! ```no_run
//! use ech_auth::*;
//! use ed25519_dalek::SigningKey;
//!
//! # fn main() -> ech_auth::Result<()> {
//! // 1. Create ECH config
//! let config = ECHConfigBuilder::new()
//!     .config_id(1)
//!     .kem_id(0x0020) // X25519
//!     .public_key(vec![0u8; 32])
//!     .add_cipher_suite(0x0001, 0x0001)
//!     .public_name("example.com")
//!     .build()?;
//!
//! // 2. Sign with RPK
//! # let your_ed25519_key = [0u8; 32];
//! let signing_key = SigningKey::from_bytes(&your_ed25519_key);
//! let not_after = 1735689600; // Unix timestamp
//! let sig = sign_rpk(&config.encode(), &signing_key, not_after);
//!
//! // 3. Create auth extension
//! let auth = ECHAuth {
//!     method: ECHAuthMethod::Rpk,
//!     trusted_keys: vec![],
//!     signature: Some(sig),
//! };
//!
//! // 4. Create signed config
//! let signed_config = config.with_ech_auth(&auth);
//! # Ok(())
//! # }
//! ```
//!
//! ## Handling ECH Rejection with Retry Config
//!
//! ```no_run
//! use ech_auth::*;
//!
//! # fn main() -> ech_auth::Result<()> {
//! # let retry_config_bytes = &[0u8; 100];
//! # let pinned_spki_hash = [0u8; 32];
//! # let current_time = 1700000000;
//! // 1. Server rejected ECH, sent retry_config
//! let retry_config = ECHConfig::decode(retry_config_bytes)?;
//! let retry_auth = retry_config.extract_ech_auth()?;
//!
//! // 2. Evaluate trust for retry config
//! let result = evaluate_trust(&EvaluateTrustInput {
//!     config: &retry_config,
//!     auth: retry_auth.as_ref(),
//!     from_dns: false, // From TLS retry, not DNS
//!     dns_confirms_ech: false,
//!     dns_rpk_anchor: Some(pinned_spki_hash),
//!     pkix_roots: vec![],
//!     now: current_time,
//! });
//!
//! // 3. Only retry if accepted
//! if result.decision == TrustDecision::Accept {
//!     // Attempt 2nd handshake with validated retry config
//! }
//! # Ok(())
//! # }
//! ```
//!
//! See the [`examples/`](https://github.com/grittygrease/ech-auth-interop/tree/main/rust/examples)
//! directory for more detailed usage patterns.
//!
//! # Wire Format Support
//!
//! This library supports two wire format versions:
//!
//! - **Combined format** ([`ECHAuth`]) - Legacy format from draft -00
//! - **Split format** ([`ECHAuthInfo`] + [`ECHAuthRetry`]) - PR #2 format
//!
//! The combined format is used by default for interoperability. The split
//! format separates policy (trusted_keys) from signature for DNS efficiency.
//!
//! # Feature Flags
//!
//! Currently no optional features. All functionality is included by default.
//!
//! # Security Considerations
//!
//! - **Time validation**: Enforces `not_after` expiration for all signatures
//! - **Algorithm agility**: Supports multiple signature algorithms
//! - **Fail-closed**: Empty trust anchors reject all configs
//! - **Downgrade protection**: Config cache prevents unsigned downgrades
//! - **Extension ordering**: Validates ech_auth is last extension (MUST requirement)
//!
//! # Compliance
//!
//! This implementation is fully compliant with draft-sullivan-tls-signed-ech-updates:
//! - ✅ Extension ordering validation (Section 5.1)
//! - ✅ SAN matching for PKIX
//! - ✅ PKIX not_after=0 enforcement
//! - ✅ Trust model with DNS confirmation
//! - ✅ Downgrade attack prevention

mod codec;
mod ech_config;
mod error;
mod sign;
mod types;
mod verify;

mod trust;

pub use codec::detect_version;
pub use ech_config::*;
pub use error::{Error, Result};
pub use sign::{
    encode_ecdsa_p256_spki, encode_ed25519_spki, sign_pkix_ecdsa, sign_pkix_ed25519, sign_rpk,
    sign_rpk_ecdsa,
};
pub use trust::*;
pub use types::{
    DEFAULT_SPEC_VERSION, ECDSA_SECP256R1_SHA256, ECHAuth, ECHAuthInfo, ECHAuthMethod,
    ECHAuthRetry, ECHAuthSignature, ED25519_SIGNATURE_SCHEME, SPKIHash, SpecVersion,
};
pub use verify::{verify_pkix, verify_pkix_versioned, verify_rpk};
