use crate::{ECHAuthSignature, ECDSA_SECP256R1_SHA256, ED25519_SIGNATURE_SCHEME};
use ed25519_dalek::{Signer, SigningKey};
use p256::ecdsa::SigningKey as EcdsaSigningKey;
use sha2::{Digest, Sha256};

/// Context label for ECH authentication signatures
const CONTEXT_LABEL: &[u8] = b"TLS-ECH-AUTH-v1";

/// Ed25519 SPKI prefix (DER encoding of AlgorithmIdentifier + BIT STRING header)
///
/// Structure:
/// ```text
/// 30 2a                          ; SEQUENCE (42 bytes total)
///    30 05                       ; SEQUENCE (5 bytes) - AlgorithmIdentifier
///       06 03 2b 65 70           ; OID 1.3.101.112 (Ed25519)
///    03 21 00                    ; BIT STRING (33 bytes, 0 unused bits)
///       <32 bytes of public key>
/// ```
pub const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, // SEQUENCE (42 bytes)
    0x30, 0x05, // SEQUENCE (5 bytes)
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
    0x03, 0x21, 0x00, // BIT STRING (33 bytes, 0 unused)
];

/// ECDSA P-256 SPKI prefix (DER encoding of AlgorithmIdentifier + BIT STRING header)
///
/// Structure:
/// ```text
/// 30 59                          ; SEQUENCE (89 bytes)
///    30 13                       ; SEQUENCE (19 bytes) - AlgorithmIdentifier
///       06 07 2a 86 48 ce 3d 02 01   ; OID 1.2.840.10045.2.1 (ecPublicKey)
///       06 08 2a 86 48 ce 3d 03 01 07 ; OID 1.2.840.10045.3.1.7 (secp256r1)
///    03 42 00                    ; BIT STRING (66 bytes, 0 unused)
///       04 <64 bytes of uncompressed point>
/// ```
pub const ECDSA_P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, // SEQUENCE (89 bytes)
    0x30, 0x13, // SEQUENCE (19 bytes)
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID 1.2.840.10045.2.1
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID 1.2.840.10045.3.1.7
    0x03, 0x42, 0x00, // BIT STRING (66 bytes, 0 unused)
];

/// Encode Ed25519 public key as DER-encoded SPKI
pub fn encode_ed25519_spki(public_key: &[u8; 32]) -> Vec<u8> {
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&ED25519_SPKI_PREFIX);
    spki.extend_from_slice(public_key);
    spki
}

/// Encode ECDSA P-256 public key as DER-encoded SPKI
pub fn encode_ecdsa_p256_spki(public_key: &[u8; 65]) -> Vec<u8> {
    let mut spki = Vec::with_capacity(91);
    spki.extend_from_slice(&ECDSA_P256_SPKI_PREFIX);
    spki.extend_from_slice(public_key);
    spki
}

/// Sign an ECHConfig with RPK method
///
/// # Arguments
/// * `ech_config_tbs` - The ECHConfig bytes with ech_auth.signature set to zero-length
/// * `signing_key` - Ed25519 signing key
/// * `not_after` - Expiration timestamp (Unix epoch seconds)
///
/// # Returns
/// ECHAuthSignature to embed in the ECHAuth extension
pub fn sign_rpk(
    ech_config_tbs: &[u8],
    signing_key: &SigningKey,
    not_after: u64,
) -> ECHAuthSignature {
    // Build the authenticator (SPKI)
    let public_key = signing_key.verifying_key();
    let spki = encode_ed25519_spki(public_key.as_bytes());

    // Build to_be_signed = context_label || ech_config_tbs
    let mut to_be_signed = Vec::with_capacity(CONTEXT_LABEL.len() + ech_config_tbs.len());
    to_be_signed.extend_from_slice(CONTEXT_LABEL);
    to_be_signed.extend_from_slice(ech_config_tbs);

    // Sign
    let signature = signing_key.sign(&to_be_signed);

    ECHAuthSignature {
        authenticator: spki,
        not_after,
        algorithm: ED25519_SIGNATURE_SCHEME,
        signature: signature.to_bytes().to_vec(),
    }
}

/// Sign an ECHConfig with RPK method using ECDSA P-256
///
/// # Arguments
/// * `ech_config_tbs` - The ECHConfig bytes with ech_auth.signature set to zero-length
/// * `signing_key` - ECDSA P-256 signing key
/// * `not_after` - Expiration timestamp (Unix epoch seconds)
///
/// # Returns
/// ECHAuthSignature to embed in the ECHAuth extension
pub fn sign_rpk_ecdsa(
    ech_config_tbs: &[u8],
    signing_key: &EcdsaSigningKey,
    not_after: u64,
) -> ECHAuthSignature {
    // Build the authenticator (SPKI)
    let public_key = signing_key.verifying_key();
    let public_key_bytes = public_key.to_encoded_point(false);
    let mut pk_array = [0u8; 65];
    pk_array.copy_from_slice(public_key_bytes.as_bytes());
    let spki = encode_ecdsa_p256_spki(&pk_array);

    // Build to_be_signed = context_label || ech_config_tbs
    let mut to_be_signed = Vec::with_capacity(CONTEXT_LABEL.len() + ech_config_tbs.len());
    to_be_signed.extend_from_slice(CONTEXT_LABEL);
    to_be_signed.extend_from_slice(ech_config_tbs);

    // ECDSA with SHA-256 - we need to hash first, then sign the hash
    let mut hasher = Sha256::new();
    hasher.update(&to_be_signed);
    let hash = hasher.finalize();

    // Sign the hash directly (not using Signer trait which may double-hash)
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&hash)
        .expect("failed to sign");

    ECHAuthSignature {
        authenticator: spki,
        not_after,
        algorithm: ECDSA_SECP256R1_SHA256,
        signature: signature.to_der().as_bytes().to_vec(),
    }
}

/// Sign an ECHConfig with PKIX method
///
/// # Arguments
/// * `ech_config_tbs` - The ECHConfig bytes with ech_auth.signature set to zero-length
/// * `signing_key` - The private key (Ed25519 or ECDSA P-256)
/// * `certificate_chain` - DER-encoded certificates (leaf first)
///
/// For PKIX, not_after is always 0 (use certificate validity instead)
pub fn sign_pkix_ed25519(
    ech_config_tbs: &[u8],
    signing_key: &SigningKey,
    certificate_chain: Vec<Vec<u8>>,
) -> ECHAuthSignature {
    // Build the authenticator (certificate chain)
    // Format: length-prefixed list of DER certificates
    let mut authenticator = Vec::new();
    for cert in &certificate_chain {
        authenticator.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..4]); // 24-bit length
        authenticator.extend_from_slice(cert);
    }

    // Build to_be_signed = context_label || ech_config_tbs
    let mut to_be_signed = Vec::with_capacity(CONTEXT_LABEL.len() + ech_config_tbs.len());
    to_be_signed.extend_from_slice(CONTEXT_LABEL);
    to_be_signed.extend_from_slice(ech_config_tbs);

    // Sign
    let signature = signing_key.sign(&to_be_signed);

    ECHAuthSignature {
        authenticator,
        not_after: 0, // Use certificate validity
        algorithm: ED25519_SIGNATURE_SCHEME,
        signature: signature.to_bytes().to_vec(),
    }
}

/// Sign an ECHConfig with PKIX method using ECDSA P-256
///
/// # Arguments
/// * `ech_config_tbs` - The ECHConfig bytes with ech_auth.signature set to zero-length
/// * `signing_key` - ECDSA P-256 signing key
/// * `certificate_chain` - DER-encoded certificates (leaf first)
///
/// For PKIX, not_after is always 0 (use certificate validity instead)
pub fn sign_pkix_ecdsa(
    ech_config_tbs: &[u8],
    signing_key: &EcdsaSigningKey,
    certificate_chain: Vec<Vec<u8>>,
) -> ECHAuthSignature {
    // Build the authenticator (certificate chain)
    // Format: length-prefixed list of DER certificates
    let mut authenticator = Vec::new();
    for cert in &certificate_chain {
        authenticator.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..4]); // 24-bit length
        authenticator.extend_from_slice(cert);
    }

    // Build to_be_signed = context_label || ech_config_tbs
    let mut to_be_signed = Vec::with_capacity(CONTEXT_LABEL.len() + ech_config_tbs.len());
    to_be_signed.extend_from_slice(CONTEXT_LABEL);
    to_be_signed.extend_from_slice(ech_config_tbs);

    // ECDSA with SHA-256 - we need to hash first, then sign the hash
    let mut hasher = Sha256::new();
    hasher.update(&to_be_signed);
    let hash = hasher.finalize();

    // Sign the hash directly (not using Signer trait which may double-hash)
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&hash)
        .expect("failed to sign");

    ECHAuthSignature {
        authenticator,
        not_after: 0, // Use certificate validity
        algorithm: ECDSA_SECP256R1_SHA256,
        signature: signature.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use p256::ecdsa::SigningKey as EcdsaSigningKey;

    #[test]
    fn test_encode_ed25519_spki() {
        let public_key = [42u8; 32];
        let spki = encode_ed25519_spki(&public_key);

        // Check length (12 prefix + 32 key = 44)
        assert_eq!(spki.len(), 44);

        // Check prefix
        assert_eq!(&spki[..12], &ED25519_SPKI_PREFIX);

        // Check public key
        assert_eq!(&spki[12..], &public_key);
    }

    #[test]
    fn test_sign_rpk() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let ech_config_tbs = b"test config";
        let not_after = 1234567890;

        let sig = sign_rpk(ech_config_tbs, &signing_key, not_after);

        assert_eq!(sig.algorithm, ED25519_SIGNATURE_SCHEME);
        assert_eq!(sig.not_after, not_after);
        assert_eq!(sig.authenticator.len(), 44); // SPKI length
        assert_eq!(sig.signature.len(), 64); // Ed25519 signature length
    }

    #[test]
    fn test_sign_rpk_deterministic() {
        // Same input should produce same signature (Ed25519 is deterministic)
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let ech_config_tbs = b"deterministic test";
        let not_after = 9999999999;

        let sig1 = sign_rpk(ech_config_tbs, &signing_key, not_after);
        let sig2 = sign_rpk(ech_config_tbs, &signing_key, not_after);

        assert_eq!(sig1.signature, sig2.signature);
        assert_eq!(sig1.authenticator, sig2.authenticator);
    }

    #[test]
    fn test_encode_ecdsa_p256_spki() {
        let public_key = [4u8; 65]; // 0x04 prefix + 64 bytes
        let spki = encode_ecdsa_p256_spki(&public_key);

        // Check length (26 prefix + 65 key = 91)
        assert_eq!(spki.len(), 91);

        // Check prefix
        assert_eq!(&spki[..26], &ECDSA_P256_SPKI_PREFIX);

        // Check public key
        assert_eq!(&spki[26..], &public_key);
    }

    #[test]
    fn test_sign_rpk_ecdsa() {
        use p256::SecretKey;

        let secret_key = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let signing_key = EcdsaSigningKey::from(secret_key);
        let ech_config_tbs = b"test config ecdsa";
        let not_after = 1234567890;

        let sig = sign_rpk_ecdsa(ech_config_tbs, &signing_key, not_after);

        assert_eq!(sig.algorithm, ECDSA_SECP256R1_SHA256);
        assert_eq!(sig.not_after, not_after);
        assert_eq!(sig.authenticator.len(), 91); // SPKI length for P-256
        // ECDSA signature is DER-encoded, typically 70-72 bytes
        assert!(sig.signature.len() >= 64 && sig.signature.len() <= 72);
    }

    #[test]
    fn test_sign_pkix_ed25519() {
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let ech_config_tbs = b"test config pkix";
        let cert = vec![0x30, 0x82, 0x01, 0x00]; // Dummy cert
        let chain = vec![cert.clone()];

        let sig = sign_pkix_ed25519(ech_config_tbs, &signing_key, chain);

        assert_eq!(sig.algorithm, ED25519_SIGNATURE_SCHEME);
        assert_eq!(sig.not_after, 0); // PKIX uses certificate validity
        assert!(sig.authenticator.len() > 0);
        assert_eq!(sig.signature.len(), 64);
    }

    #[test]
    fn test_sign_pkix_ecdsa() {
        use p256::SecretKey;

        let secret_key = SecretKey::from_slice(&[4u8; 32]).unwrap();
        let signing_key = EcdsaSigningKey::from(secret_key);
        let ech_config_tbs = b"test config pkix ecdsa";
        let cert = vec![0x30, 0x82, 0x01, 0x00]; // Dummy cert
        let chain = vec![cert.clone()];

        let sig = sign_pkix_ecdsa(ech_config_tbs, &signing_key, chain);

        assert_eq!(sig.algorithm, ECDSA_SECP256R1_SHA256);
        assert_eq!(sig.not_after, 0); // PKIX uses certificate validity
        assert!(sig.authenticator.len() > 0);
        assert!(sig.signature.len() >= 64 && sig.signature.len() <= 72);
    }
}
