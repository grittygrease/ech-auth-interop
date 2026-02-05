# ECH Auth - Rust Implementation

[![Crates.io](https://img.shields.io/crates/v/ech-auth.svg)](https://crates.io/crates/ech-auth)
[![Documentation](https://docs.rs/ech-auth/badge.svg)](https://docs.rs/ech-auth)
[![License](https://img.shields.io/crates/l/ech-auth.svg)](../LICENSE-MIT)

Rust implementation of [draft-sullivan-tls-signed-ech-updates](https://datatracker.ietf.org/doc/draft-sullivan-tls-signed-ech-updates/) for authenticated ECH configuration distribution.

## What is ECH Authentication?

ECH (Encrypted Client Hello) authentication extends the ECH protocol with cryptographic signatures to prevent downgrade attacks and ensure configuration authenticity. This allows TLS clients to verify that ECH retry configs received during handshake rejection come from the legitimate server operator.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
ech-auth = "0.1"
```

## Quick Start

### As a TLS Client (High-Level Trust Model)

The trust model API handles policy decisions including DNS confirmation and downgrade protection:

```rust
use ech_auth::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Receive ECH config from DNS
    let config = ECHConfig::decode(&dns_echconfig_bytes)?;
    
    // 2. Extract ech_auth extension (if present)
    let auth = config.extract_ech_auth()?;
    
    // 3. Evaluate trust with DNS-provided SPKI hash
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    
    let result = evaluate_trust(&EvaluateTrustInput {
        config: &config,
        auth: auth.as_ref(),
        from_dns: true,
        dns_confirms_ech: true,
        dns_rpk_anchor: Some(pinned_spki_hash),
        pkix_roots: vec![],
        now: current_time,
    });
    
    // 4. Act on decision
    match result.decision {
        TrustDecision::Accept => {
            // Use the validated ECH config for your connection
            println!("✓ ECH config accepted");
        }
        TrustDecision::GREASE => {
            // Send GREASE ECH instead (preserve privacy)
            println!("⚠ Sending GREASE ECH");
        }
        TrustDecision::Reject => {
            // Signature verification failed
            println!("✗ ECH config rejected");
        }
    }
    
    Ok(())
}
```

### As a Server (Signing Configs)

Sign ECH configs to enable client verification:

```rust
use ech_auth::*;
use ed25519_dalek::SigningKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create ECH config
    let config = ECHConfigBuilder::new()
        .config_id(1)
        .kem_id(0x0020) // X25519
        .public_key(vec![0u8; 32]) // Your HPKE public key
        .add_cipher_suite(0x0001, 0x0001) // HKDF-SHA256, AES-128-GCM
        .public_name("example.com")
        .build()?;
    
    // 2. Sign with RPK (Raw Public Key)
    let signing_key = SigningKey::from_bytes(&your_ed25519_key);
    let not_after = 1735689600; // Unix timestamp (expiration)
    let sig = sign_rpk(&config.encode(), &signing_key, not_after);
    
    // 3. Create auth extension
    let auth = ECHAuth {
        method: ECHAuthMethod::Rpk,
        trusted_keys: vec![], // Populated in DNS, empty in TLS
        signature: Some(sig),
    };
    
    // 4. Create signed config
    let signed_config = config.with_ech_auth(&auth);
    
    // 5. Distribute via TLS retry_config
    // send_retry_config(signed_config);
    
    Ok(())
}
```

### Low-Level API (Direct Verification)

For custom trust logic, use the verification functions directly:

```rust
use ech_auth::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Direct RPK verification (no trust policy)
    let config_tbs = config.encode(); // To-be-signed bytes
    verify_rpk(&config_tbs, &ech_auth, current_time)?;
    
    // Direct PKIX verification
    verify_pkix(
        &config_tbs,
        &ech_auth,
        "example.com", // public_name
        &root_cert_ders,
        current_time,
    )?;
    
    Ok(())
}
```

## Architecture

### Trust Model API vs Verification API

This library provides two API levels:

**Trust Model API** (Recommended for TLS Clients):
- `evaluate_trust()` - High-level trust decision with DNS confirmation and downgrade protection
- `ConfigCache` - Cache validated configs to prevent downgrades
- `TrustDecision` - Accept/GREASE/Reject result
- `EvaluateTrustInput` - Input parameters

**Verification API** (For Custom Logic):
- `verify_rpk()` - Direct RPK signature verification
- `verify_pkix()` - Direct PKIX certificate chain verification

Use the **Trust Model API** unless you're implementing custom trust logic. The verification API only checks cryptographic signatures without handling DNS confirmation or downgrade attacks.

### Wire Format Types

This library supports two wire format versions:

**Combined Format** (`ECHAuth`):
- Legacy format from draft -00
- Single extension for all contexts
- Used by default for interoperability

**Split Format** (`ECHAuthInfo` + `ECHAuthRetry`):
- PR #2 format
- `ECHAuthInfo` - Policy (trusted_keys) in DNS
- `ECHAuthRetry` - Signature in TLS retry_config
- More efficient for DNS distribution

The combined format is recommended for simplicity unless you need DNS optimization.

## Authentication Methods

### RPK (Raw Public Key)

Uses SPKI hash pinning similar to HPKP/DANE. Clients pin SHA-256 hashes of trusted public keys.

**Supported algorithms:**
- Ed25519 (recommended)
- ECDSA P-256 (secp256r1)

**When to use:**
- Simple deployments
- Direct key pinning
- Avoiding PKI complexity

### PKIX (Certificate Chain)

Uses X.509 certificate chains with WebPKI validation. Requires certificates with the critical `id-pe-echConfigSigning` extension (OID 1.3.6.1.5.5.7.1.99).

**When to use:**
- Existing PKI infrastructure
- Certificate rotation via CA
- Enterprise deployments

## Integration with TLS Stacks

This library is TLS-stack agnostic. It provides:
- ECH config parsing and encoding
- Signature verification
- Trust decision logic

You integrate it with your TLS stack (rustls, OpenSSL, etc.) by:
1. Extracting ECH configs from DNS or retry_config
2. Calling `evaluate_trust()` or verification functions
3. Acting on the trust decision

See [`INTEGRATION.md`](../INTEGRATION.md) for detailed integration patterns with popular TLS stacks.

## Examples

The `examples/` directory contains complete usage patterns:

- **`client_trust_model.rs`** - Full client flow with trust evaluation
- **`server_signing.rs`** - Server signing ECH configs
- **`retry_config_handling.rs`** - ECH rejection and retry flow
- **`pkix_validation.rs`** - PKIX certificate chain validation

Run an example:
```bash
cargo run --example client_trust_model
```

## CLI Tools

The library includes command-line tools for testing and interoperability:

```bash
# Generate a signing key
cargo run --bin ech-generate -- --algorithm ed25519 --output key.json

# Sign an ECH config
cargo run --bin ech-sign -- --key key.json --config config.bin --output signed.bin

# Verify a signed config
cargo run --bin ech-verify -- --config signed.bin --trusted-key <spki-hash-hex>
```

## API Documentation

Comprehensive API documentation is available at [docs.rs/ech-auth](https://docs.rs/ech-auth).

Key modules:
- `ech_auth` - Root module with overview and examples
- `ech_auth::trust` - Trust model and policy decisions
- `ech_auth::verify` - Low-level verification functions
- `ech_auth::sign` - Signing functions for servers
- `ech_auth::types` - Wire format data structures

## Testing

Run the test suite:
```bash
cargo test
```

This includes:
- 27 unit tests covering wire formats, signing, verification
- 5 protocol E2E tests simulating full ECH handshake flows
- Trust model tests with 9 scenarios

## Compliance

This implementation is compliant with draft-sullivan-tls-signed-ech-updates with:
- ✅ Extension ordering validation (ech_auth must be last)
- ✅ SAN matching for PKIX
- ✅ PKIX not_after=0 enforcement
- ✅ Downgrade attack prevention

See [`COMPLIANCE.md`](../COMPLIANCE.md) for detailed compliance status.

## Security Considerations

- **Time validation**: All implementations enforce `not_after` expiration
- **Algorithm agility**: Supports Ed25519 and ECDSA P-256
- **Fail-closed**: Empty trust anchors reject all configs (no silent fallback)
- **Downgrade protection**: Config cache prevents unsigned downgrades
- **SPKI pinning**: SHA-256 of SubjectPublicKeyInfo

## Contributing

Contributions welcome! This is a reference implementation for interoperability testing.

When contributing:
1. Run `cargo clippy` and `cargo fmt`
2. Add tests for new functionality
3. Update documentation

## License

MIT OR Apache-2.0 (see [`LICENSE-MIT`](../LICENSE-MIT) and [`LICENSE-APACHE`](../LICENSE-APACHE))

## See Also

- [Go implementation](../go/) - Reference implementation with E2E TLS tests
- [NSS implementation](../nss/) - C implementation for NSS library
- [Draft specification](https://datatracker.ietf.org/doc/draft-sullivan-tls-signed-ech-updates/)
- [Interop testing](../interop/) - Cross-implementation validation
