//! Example: PKIX certificate-based authentication
//!
//! This example demonstrates PKIX (X.509 certificate chain) authentication
//! for ECH configs. Note: This example shows the API usage; actual certificate
//! generation requires additional tools.
//!
//! Run: cargo run --example pkix_validation

use ech_auth::*;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("ECH Authentication - PKIX Certificate Validation");
    println!("===============================================\n");

    println!("=== PKIX Authentication Overview ===");
    println!("PKIX uses X.509 certificate chains for authentication.");
    println!("Requirements:");
    println!("  • Leaf certificate must have critical id-pe-echConfigSigning extension");
    println!("  • Certificate SAN must match ECH config public_name");
    println!("  • Chain must validate against provided trust anchors");
    println!("  • not_after timestamp required for replay protection (PR #2)");

    // Step 1: Setup (in production, you'd have real certificates)
    println!("\n=== Step 1: Certificate Setup ===");
    println!("In production, you would:");
    println!("  1. Generate certificate with id-pe-echConfigSigning extension");
    println!("  2. Get certificate signed by CA");
    println!("  3. Distribute root CA certificate to clients");
    println!("\nFor this example, we'll show the API usage with placeholder data.");

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);

    // In production: load_certificate_chain()
    let certificate_der = vec![0x30, 0x82, 0x01, 0x00]; // Placeholder
    let root_cert_der = certificate_der.clone(); // Placeholder

    println!("  Certificate chain prepared (placeholder)");
    println!("  Root CA: {} bytes", root_cert_der.len());

    // Step 2: Create ECH config
    println!("\n=== Step 2: Create ECH Config ===");
    let config = ECHConfigBuilder::new()
        .config_id(1)
        .kem_id(0x0020)
        .public_key(vec![0u8; 32])
        .add_cipher_suite(0x0001, 0x0001)
        .public_name("example.com")
        .build()?;
    println!("✓ ECH config created for: {}", config.public_name);

    // Step 3: Sign with PKIX method
    println!("\n=== Step 3: Sign Config (PKIX Method) ===");

    // Per PR #2: not_after is required for both RPK and PKIX (replay protection)
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let not_after = current_time + 86400; // Valid for 24 hours

    let sig = sign_pkix_ed25519(
        &config.encode(),
        &signing_key,
        vec![certificate_der.clone()],
        not_after,
    );

    println!("✓ Config signed with PKIX");
    println!("  Algorithm: 0x{:04x} (Ed25519)", sig.algorithm);
    println!("  not_after: {} (Unix timestamp)", sig.not_after);
    println!("  Certificate chain: {} bytes", sig.authenticator.len());

    // Step 4: Create auth extension
    let _auth = ECHAuth {
        method: ECHAuthMethod::Pkix,
        trusted_keys: vec![], // Empty for PKIX
        signature: Some(sig),
    };

    println!("\n=== Step 4: Client Validation ===");
    println!("Client would validate by calling evaluate_trust():");
    println!();
    println!("  let result = evaluate_trust(&EvaluateTrustInput {{");
    println!("      config: &config,");
    println!("      auth: Some(&auth),");
    println!("      from_dns: true,");
    println!("      dns_confirms_ech: true,");
    println!("      dns_rpk_anchor: None,");
    println!("      pkix_roots: vec![root_cert_der], // Trust anchor");
    println!("      now: current_time,");
    println!("  }});");
    println!();
    println!("The trust model will:");
    println!("  1. Parse certificate chain from signature");
    println!("  2. Validate critical id-pe-echConfigSigning extension");
    println!("  3. Check SAN matches public_name");
    println!("  4. Validate chain against trust anchors (WebPKI)");
    println!("  5. Verify signature with leaf certificate public key");
    println!("  6. Return Accept if DNS confirms, GREASE otherwise");

    // Step 5: Key differences from RPK
    println!("\n=== PKIX vs RPK ===");
    println!();
    println!("RPK (Raw Public Key):");
    println!("  • Simple SPKI hash pinning");
    println!("  • No certificate infrastructure needed");
    println!("  • not_after controls expiration");
    println!("  • Direct key rotation via DNS");
    println!();
    println!("PKIX (Certificate Chain):");
    println!("  • Full X.509 certificate validation");
    println!("  • Leverages existing PKI");
    println!("  • not_after provides replay protection (PR #2)");
    println!("  • Requires id-pe-echConfigSigning extension");

    println!("\n=== Summary ===");
    println!("PKIX authentication provides:");
    println!("  • Integration with existing PKI infrastructure");
    println!("  • Certificate rotation via CA");
    println!("  • Standard WebPKI validation");
    println!("  • Enterprise-grade trust chains");
    println!(
        "\nUse sign_pkix_ed25519() or sign_pkix_ecdsa() with valid not_after for PKIX signing."
    );

    Ok(())
}
