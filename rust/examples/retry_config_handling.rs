//! Example: Handling ECH rejection with authenticated retry config
//!
//! This example demonstrates the full ECH rejection and retry flow,
//! showing how clients should handle authenticated retry configs.
//!
//! Run: cargo run --example retry_config_handling

use ech_auth::*;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("ECH Authentication - Retry Config Handling");
    println!("==========================================\n");

    // Initialize client state
    let mut cache = ConfigCache::new();
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let spki_hash = compute_spki_hash(&signing_key);

    println!("=== Scenario: ECH Rejection with Authenticated Retry ===\n");

    // Step 1: Initial connection attempt
    println!("Step 1: Client attempts ECH connection");
    let initial_config = create_ech_config("example.com", 1);
    println!(
        "  → Connecting to example.com with ECH config ID {}",
        initial_config.config_id
    );
    println!("  → Server rejects ECH (e.g., key was rotated)\n");

    // Step 2: Server sends retry_config
    println!("Step 2: Server sends retry_config with new key");
    let retry_config = create_ech_config("example.com", 2); // New config ID
    let retry_sig = sign_rpk(&retry_config.encode(), &signing_key, current_time() + 86400);
    let retry_auth = ECHAuth {
        method: ECHAuthMethod::Rpk,
        trusted_keys: vec![spki_hash],
        signature: Some(retry_sig),
    };
    println!("  ← Server sends retry_config with signature");
    println!("    Config ID: {}", retry_config.config_id);
    println!(
        "    Signature algorithm: 0x{:04x}",
        retry_auth.signature.as_ref().unwrap().algorithm
    );

    // Step 3: Client validates retry_config
    println!("\nStep 3: Client validates retry_config signature");
    let result = evaluate_trust(&EvaluateTrustInput {
        config: &retry_config,
        auth: Some(&retry_auth),
        from_dns: false, // Important: retry config is NOT from DNS
        dns_confirms_ech: false,
        dns_rpk_anchor: Some(spki_hash), // Client has pinned SPKI from DNS
        pkix_roots: vec![],
        now: current_time(),
    });

    println!("  Trust Decision: {:?}", result.decision);
    println!("  Reason: {}", result.reason);

    // Step 4: Handle decision
    println!("\nStep 4: Client acts on trust decision");
    if result.decision == TrustDecision::Accept {
        println!("  ✓ Retry config accepted!");

        // Cache the validated config
        if let Some(validated) = result.validated_config {
            cache.put(validated);
            println!("  ✓ Config cached for downgrade protection");
        }

        println!("\nStep 5: Client attempts 2nd handshake");
        println!("  → Reconnecting with validated retry_config");
        println!("  → ECH succeeds with new config");
    } else {
        println!("  ✗ Retry config rejected - aborting connection");
        println!("  Reason: {}", result.reason);
    }

    // Demonstrate attack scenario
    println!("\n\n=== Scenario: Attacker Tries Malicious Retry Config ===\n");

    println!("Step 1: Attacker intercepts connection");
    println!("  → Client attempts ECH");
    println!("  → Attacker sends fake retry_config with wrong signature\n");

    let attacker_key = SigningKey::from_bytes(&[99u8; 32]);
    let malicious_config = create_ech_config("evil.com", 3);
    let malicious_sig = sign_rpk(
        &malicious_config.encode(),
        &attacker_key,
        current_time() + 86400,
    );
    let malicious_auth = ECHAuth {
        method: ECHAuthMethod::Rpk,
        trusted_keys: vec![],
        signature: Some(malicious_sig),
    };

    println!("Step 2: Client validates attacker's retry_config");
    let attack_result = evaluate_trust(&EvaluateTrustInput {
        config: &malicious_config,
        auth: Some(&malicious_auth),
        from_dns: false,
        dns_confirms_ech: false,
        dns_rpk_anchor: Some(spki_hash), // Pinned legitimate SPKI
        pkix_roots: vec![],
        now: current_time(),
    });

    println!("  Trust Decision: {:?}", attack_result.decision);
    println!("  Reason: {}", attack_result.reason);

    if attack_result.decision == TrustDecision::Reject {
        println!("\n  ✓ Attack prevented! Signature doesn't match pinned SPKI.");
        println!("  ✓ Client refuses to use malicious config.");
    }

    println!("\n=== Key Takeaways ===");
    println!("• Always evaluate retry_config signatures");
    println!("• Pin SPKI hashes from DNS for RPK validation");
    println!("• Cache validated configs to detect downgrades");
    println!("• Reject retry configs with invalid signatures");
    println!("• Set from_dns=false for retry configs");

    Ok(())
}

fn create_ech_config(public_name: &str, config_id: u8) -> ECHConfig {
    ECHConfigBuilder::new()
        .config_id(config_id)
        .kem_id(0x0020)
        .public_key(vec![0u8; 32])
        .add_cipher_suite(0x0001, 0x0001)
        .public_name(public_name)
        .build()
        .unwrap()
}

fn compute_spki_hash(signing_key: &SigningKey) -> SPKIHash {
    let spki = encode_ed25519_spki(signing_key.verifying_key().as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&spki);
    hasher.finalize().into()
}

fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
