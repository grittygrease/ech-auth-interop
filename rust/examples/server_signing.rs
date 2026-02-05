//! Example: Server signing ECH configurations
//!
//! This example demonstrates how a server should sign ECH configurations
//! for distribution via DNS and TLS retry configs.
//!
//! Run: cargo run --example server_signing

use ech_auth::*;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("ECH Authentication - Server Signing Example");
    println!("============================================\n");

    // Step 1: Generate or load signing key
    println!("=== Step 1: Signing Key Setup ===");
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let public_key = signing_key.verifying_key();
    println!("✓ Ed25519 signing key loaded");
    println!("  Public key: {}", hex::encode(public_key.as_bytes()));

    // Compute SPKI hash for client pinning
    let spki = encode_ed25519_spki(public_key.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&spki);
    let spki_hash: SPKIHash = hasher.finalize().into();
    println!("  SPKI hash: {}", hex::encode(spki_hash));
    println!("\n  → Publish this SPKI hash in DNS HTTPS record");

    // Step 2: Create ECH config
    println!("\n=== Step 2: Create ECH Config ===");
    let config = ECHConfigBuilder::new()
        .config_id(1)
        .kem_id(0x0020) // X25519
        .public_key(vec![0u8; 32]) // Your HPKE public key
        .add_cipher_suite(0x0001, 0x0001) // HKDF-SHA256, AES-128-GCM
        .add_cipher_suite(0x0001, 0x0003) // HKDF-SHA256, ChaCha20-Poly1305
        .maximum_name_length(64)
        .public_name("example.com")
        .build()?;
    println!("✓ ECH config created");
    println!("  Public name: {}", config.public_name);
    println!("  Config ID: {}", config.config_id);
    println!("  Cipher suites: {}", config.cipher_suites.len());

    // Step 3: Sign with RPK method
    println!("\n=== Step 3: Sign Config (RPK Method) ===");
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let not_after = current_time + 86400; // Valid for 24 hours

    let sig = sign_rpk(&config.encode(), &signing_key, not_after);
    println!("✓ Config signed with RPK");
    println!("  Algorithm: 0x{:04x} (Ed25519)", sig.algorithm);
    println!("  Valid until: {} (Unix timestamp)", sig.not_after);
    println!("  Signature length: {} bytes", sig.signature.len());

    // Step 4: Create auth extension
    println!("\n=== Step 4: Create Auth Extension ===");
    let auth = ECHAuth {
        method: ECHAuthMethod::Rpk,
        trusted_keys: vec![spki_hash], // For DNS distribution
        signature: Some(sig),
    };
    println!("✓ Auth extension created");
    println!("  Method: {:?}", auth.method);
    println!("  Trusted keys: {}", auth.trusted_keys.len());

    // Step 5: Add auth to config
    println!("\n=== Step 5: Create Signed Config ===");
    let signed_config = config.with_ech_auth(&auth);
    println!("✓ Signed ECH config created");
    println!("  Total size: {} bytes", signed_config.len());

    // Step 6: Distribution
    println!("\n=== Step 6: Distribution ===");
    println!("DNS (HTTPS record):");
    println!("  - Publish base64-encoded signed config");
    println!("  - Include SPKI hash in ech_authinfo extension");
    println!("\nTLS retry_config:");
    println!("  - Send signed config in ECH rejection response");
    println!("  - Include signature in ech_auth extension");

    // Optional: Demonstrate ECDSA P-256 signing
    println!("\n=== Alternative: ECDSA P-256 Signing ===");
    use p256::ecdsa::SigningKey as EcdsaSigningKey;
    let p256_key = EcdsaSigningKey::random(&mut rand::thread_rng());
    let p256_sig = sign_rpk_ecdsa(&config.encode(), &p256_key, not_after);
    println!("✓ Config signed with ECDSA P-256");
    println!(
        "  Algorithm: 0x{:04x} (ECDSA-secp256r1-SHA256)",
        p256_sig.algorithm
    );
    println!(
        "  Signature length: {} bytes (DER-encoded)",
        p256_sig.signature.len()
    );

    println!("\n=== Summary ===");
    println!("Servers should:");
    println!("  1. Generate stable signing keys");
    println!("  2. Sign ECH configs with sign_rpk() or sign_pkix_*()");
    println!("  3. Publish SPKI hashes in DNS");
    println!("  4. Include signed configs in TLS retry responses");
    println!("  5. Rotate keys by updating DNS SPKI hashes");

    Ok(())
}
