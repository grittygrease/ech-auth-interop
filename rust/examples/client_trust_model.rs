//! Example: TLS client using trust model API
//!
//! This example demonstrates how a TLS client should integrate ECH
//! authentication with trust evaluation and config caching.
//!
//! Run: cargo run --example client_trust_model

use ech_auth::*;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("ECH Authentication - Client Trust Model Example");
    println!("================================================\n");

    // Step 1: Simulate receiving ECH config from DNS
    println!("=== Step 1: DNS Resolution ===");
    let (config, auth, spki_hash) = simulate_dns_ech_config();
    println!("✓ Received ECH config from DNS for: {}", config.public_name);
    println!("  Config ID: {}", config.config_id);
    println!("  Auth Method: {:?}", auth.method);
    println!("  SPKI Hash: {}", hex::encode(spki_hash));

    // Step 2: Evaluate trust
    println!("\n=== Step 2: Trust Evaluation ===");
    let result = evaluate_trust(&EvaluateTrustInput {
        config: &config,
        auth: Some(&auth),
        from_dns: true,
        dns_confirms_ech: true,
        dns_rpk_anchor: Some(spki_hash),
        pkix_roots: vec![],
        now: current_time(),
    });

    println!("Trust Decision: {:?}", result.decision);
    println!("Reason: {}", result.reason);

    // Step 3: Act on decision
    println!("\n=== Step 3: Action Based on Decision ===");
    match result.decision {
        TrustDecision::Accept => {
            println!("✓ ACCEPT - Using ECH config for connection");
            println!("  The signature is valid and DNS confirms ECH support.");
            println!("  Client will use this config for encrypted ClientHello.");
        }
        TrustDecision::GREASE => {
            println!("⚠ GREASE - Sending GREASE ECH instead");
            println!("  Config is valid but DNS doesn't confirm ECH, or no signature.");
            println!("  Client will send GREASE ECH to preserve privacy.");
        }
        TrustDecision::Reject => {
            println!("✗ REJECT - Config rejected");
            println!("  Signature verification failed or config is expired.");
            println!("  Client should abort or fall back to non-ECH.");
        }
    }

    // Step 4: Cache validated config
    if let Some(validated) = result.validated_config {
        println!("\n=== Step 4: Config Caching ===");
        let mut cache = ConfigCache::new();
        cache.put(validated);
        println!("✓ Config cached for: {}", config.public_name);
        println!("  Cache prevents downgrade attacks on future connections.");

        // Demonstrate downgrade protection
        println!("\n=== Step 5: Downgrade Protection Demo ===");
        let has_signed = cache.has_signed_config(&config.public_name);
        println!("Cache has signed config: {}", has_signed);

        let would_reject = cache.should_reject_downgrade(&config.public_name, None);
        println!("Would reject unsigned downgrade: {}", would_reject);
    }

    println!("\n=== Summary ===");
    println!("The trust model API provides:");
    println!("  • Cryptographic signature verification");
    println!("  • DNS confirmation checking");
    println!("  • Downgrade attack prevention");
    println!("  • Config caching across connections");
    println!("\nFor production TLS clients, always use evaluate_trust()");
    println!("instead of low-level verify_rpk()/verify_pkix() functions.");

    Ok(())
}

/// Simulate receiving an ECH config from DNS with RPK authentication
fn simulate_dns_ech_config() -> (ECHConfig, ECHAuth, SPKIHash) {
    // Create a signing key (in production, this would be server's key)
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);

    // Create ECH config
    let config = ECHConfigBuilder::new()
        .config_id(1)
        .kem_id(0x0020) // X25519
        .public_key(vec![0u8; 32])
        .add_cipher_suite(0x0001, 0x0001) // HKDF-SHA256, AES-128-GCM
        .public_name("example.com")
        .build()
        .unwrap();

    // Sign the config
    let not_after = current_time() + 86400; // Valid for 24 hours
    let sig = sign_rpk(&config.encode(), &signing_key, not_after);

    // Compute SPKI hash (this would come from DNS in production)
    let mut hasher = Sha256::new();
    hasher.update(&sig.authenticator);
    let spki_hash: SPKIHash = hasher.finalize().into();

    // Create auth extension
    let auth = ECHAuth {
        method: ECHAuthMethod::Rpk,
        trusted_keys: vec![spki_hash],
        signature: Some(sig),
    };

    (config, auth, spki_hash)
}

/// Get current Unix timestamp
fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
