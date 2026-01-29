//! Generate test vectors for cross-implementation testing

use ech_auth::{
    sign_rpk, ECHAuth, ECHAuthInfo, ECHAuthMethod, ECHAuthRetry, ED25519_SIGNATURE_SCHEME,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

fn main() {
    // Use deterministic key for reproducibility
    let key_bytes: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ];
    let signing_key = SigningKey::from_bytes(&key_bytes);

    // Deterministic ECH config TBS
    let ech_config_tbs = b"test ECH config for interop";

    // Fixed timestamp for reproducibility
    let not_after: u64 = 1893456000; // 2030-01-01

    // Sign
    let sig = sign_rpk(ech_config_tbs, &signing_key, not_after);

    // Compute SPKI hash
    let mut hasher = Sha256::new();
    hasher.update(&sig.authenticator);
    let spki_hash: [u8; 32] = hasher.finalize().into();

    // Build ECHAuth (combined format)
    let ech_auth = ECHAuth {
        method: ECHAuthMethod::Rpk,
        trusted_keys: vec![spki_hash],
        signature: Some(sig.clone()),
    };

    // Build PR #2 split format
    let auth_info = ECHAuthInfo {
        method: ECHAuthMethod::Rpk,
        trusted_keys: vec![spki_hash],
    };

    let auth_retry = ECHAuthRetry {
        method: ECHAuthMethod::Rpk,
        not_after,
        authenticator: sig.authenticator.clone(),
        algorithm: sig.algorithm,
        signature: sig.signature.clone(),
    };

    // Encode all formats
    let combined_encoded = ech_auth.encode();
    let info_encoded = auth_info.encode();
    let retry_encoded = auth_retry.encode();

    // Output as JSON
    let json = serde_json::json!({
        "name": "interop_ed25519_rpk",
        "signing_key_hex": hex::encode(&key_bytes),
        "ech_config_tbs_hex": hex::encode(ech_config_tbs),
        "not_after": not_after,
        "spki_hex": hex::encode(&sig.authenticator),
        "spki_hash_hex": hex::encode(&spki_hash),
        "signature_hex": hex::encode(&sig.signature),
        "algorithm": ED25519_SIGNATURE_SCHEME,
        // Combined format (legacy)
        "ech_auth_encoded_hex": hex::encode(&combined_encoded),
        // PR #2 split format
        "auth_info_encoded_hex": hex::encode(&info_encoded),
        "auth_retry_encoded_hex": hex::encode(&retry_encoded),
    });

    println!("{}", serde_json::to_string_pretty(&json).unwrap());

    // Also write to stderr for verification
    eprintln!("Generated test vector:");
    eprintln!("  Key: {}", hex::encode(&key_bytes));
    eprintln!("  SPKI hash: {}", hex::encode(&spki_hash));
    eprintln!("  Signature: {} bytes", sig.signature.len());
    eprintln!("  Combined: {} bytes", combined_encoded.len());
    eprintln!("  AuthInfo: {} bytes", info_encoded.len());
    eprintln!("  AuthRetry: {} bytes", retry_encoded.len());
}
