//! Example: Low-level verification API
//!
//! This example demonstrates using the low-level verify_rpk() and verify_pkix()
//! functions for custom trust logic. Most users should use evaluate_trust()
//! instead, but this shows how to build custom verification flows.
//!
//! Run: cargo run --example low_level_verification

use ech_auth::*;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("ECH Authentication - Low-Level Verification API");
    println!("==============================================\n");

    println!("=== When to Use Low-Level API ===");
    println!("Use verify_rpk()/verify_pkix() directly when:");
    println!("  • Implementing custom trust policies");
    println!("  • Testing signature verification only");
    println!("  • Building specialized clients with non-standard flows");
    println!("\nMost TLS clients should use evaluate_trust() instead!");

    // Setup
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let config = create_test_config("example.com");
    let current_time = current_time();

    // Example 1: RPK Verification
    println!("\n=== Example 1: Direct RPK Verification ===");

    let not_after = current_time + 86400;
    let sig = sign_rpk(&config.encode(), &signing_key, not_after);

    // Compute SPKI hash
    let mut hasher = Sha256::new();
    hasher.update(&sig.authenticator);
    let spki_hash: SPKIHash = hasher.finalize().into();

    let auth = ECHAuth {
        method: ECHAuthMethod::Rpk,
        trusted_keys: vec![spki_hash],
        signature: Some(sig),
    };

    println!("Calling verify_rpk() directly...");
    match verify_rpk(&config.encode(), &auth, current_time) {
        Ok(()) => {
            println!("✓ Signature verified successfully");
            println!("  Note: This only checks cryptography!");
            println!("  Does NOT check DNS confirmation or downgrade protection.");
        }
        Err(e) => {
            println!("✗ Verification failed: {}", e);
        }
    }

    // Example 2: Expired signature
    println!("\n=== Example 2: Expired Signature Detection ===");

    let expired_not_after = current_time - 3600; // Expired 1 hour ago
    let expired_sig = sign_rpk(&config.encode(), &signing_key, expired_not_after);
    let expired_auth = ECHAuth {
        method: ECHAuthMethod::Rpk,
        trusted_keys: vec![spki_hash],
        signature: Some(expired_sig),
    };

    match verify_rpk(&config.encode(), &expired_auth, current_time) {
        Ok(()) => println!("✗ Unexpected: expired signature accepted"),
        Err(Error::Expired { not_after, current }) => {
            println!("✓ Correctly rejected expired signature");
            println!("  not_after: {}", not_after);
            println!("  current: {}", current);
        }
        Err(e) => println!("✗ Unexpected error: {}", e),
    }

    // Example 3: Wrong key
    println!("\n=== Example 3: Wrong Key Detection ===");

    let wrong_key = SigningKey::from_bytes(&[99u8; 32]);
    let wrong_sig = sign_rpk(&config.encode(), &wrong_key, not_after);

    // But we trust the original key
    let wrong_auth = ECHAuth {
        method: ECHAuthMethod::Rpk,
        trusted_keys: vec![spki_hash], // Original key's hash
        signature: Some(wrong_sig),    // Wrong key's signature
    };

    match verify_rpk(&config.encode(), &wrong_auth, current_time) {
        Ok(()) => println!("✗ Unexpected: wrong key accepted"),
        Err(Error::UntrustedKey) => {
            println!("✓ Correctly rejected untrusted key");
            println!("  SPKI hash not in trusted_keys list");
        }
        Err(e) => println!("✗ Unexpected error: {}", e),
    }

    // Example 4: Custom trust logic
    println!("\n=== Example 4: Custom Trust Logic ===");
    println!("You can build custom policies using low-level API:");
    println!();

    let custom_result = custom_trust_evaluation(&config, &auth, spki_hash, current_time);
    println!("Custom policy decision: {:?}", custom_result);

    println!("\n=== API Comparison ===");
    println!();
    println!("High-Level (evaluate_trust):");
    println!("  • Handles DNS confirmation");
    println!("  • Prevents downgrade attacks");
    println!("  • Caches validated configs");
    println!("  • Returns Accept/GREASE/Reject");
    println!("  → Use for production TLS clients");
    println!();
    println!("Low-Level (verify_rpk/verify_pkix):");
    println!("  • Pure cryptographic verification");
    println!("  • No policy decisions");
    println!("  • No caching");
    println!("  • Returns Ok/Err");
    println!("  → Use for custom trust logic or testing");

    Ok(())
}

/// Custom trust evaluation using low-level API
fn custom_trust_evaluation(
    config: &ECHConfig,
    auth: &ECHAuth,
    expected_spki: SPKIHash,
    current_time: u64,
) -> &'static str {
    // Step 1: Cryptographic verification
    if verify_rpk(&config.encode(), auth, current_time).is_err() {
        return "Reject - Signature invalid";
    }

    // Step 2: Custom policy - only accept from known domains
    let allowed_domains = ["example.com", "trusted.com"];
    if !allowed_domains.contains(&config.public_name.as_str()) {
        return "Reject - Unknown domain";
    }

    // Step 3: Custom policy - check SPKI matches expected
    let actual_spki = if let Some(sig) = &auth.signature {
        let mut hasher = Sha256::new();
        hasher.update(&sig.authenticator);
        let h: SPKIHash = hasher.finalize().into();
        h
    } else {
        return "Reject - No signature";
    };

    if actual_spki != expected_spki {
        return "Reject - SPKI mismatch";
    }

    "Accept - All checks passed"
}

fn create_test_config(public_name: &str) -> ECHConfig {
    ECHConfigBuilder::new()
        .config_id(1)
        .kem_id(0x0020)
        .public_key(vec![0u8; 32])
        .add_cipher_suite(0x0001, 0x0001)
        .public_name(public_name)
        .build()
        .unwrap()
}

fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
