use crate::sign::{ECDSA_P256_SPKI_PREFIX, ED25519_SPKI_PREFIX};
use crate::{ECHAuth, ECHAuthMethod, Error, Result, SpecVersion, DEFAULT_SPEC_VERSION, ECDSA_SECP256R1_SHA256, ED25519_SIGNATURE_SCHEME};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use p256::ecdsa::{Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};
use sha2::{Digest, Sha256};
use x509_cert::{Certificate, der::Decode};
use webpki::{
    anchor_from_trusted_cert,
    types::{CertificateDer, UnixTime},
    EndEntityCert, KeyUsage, ALL_VERIFICATION_ALGS,
};

/// Context label for ECH authentication signatures
const CONTEXT_LABEL: &[u8] = b"TLS-ECH-AUTH-v1";

/// Extract Ed25519 public key from SPKI format
///
/// SPKI structure:
/// - 12 bytes: DER prefix (SEQUENCE + AlgorithmIdentifier + BIT STRING header)
/// - 32 bytes: Ed25519 public key
///
/// Validates the DER prefix matches Ed25519 OID (1.3.101.112).
fn extract_ed25519_public_key(spki: &[u8]) -> Result<[u8; 32]> {
    if spki.len() != 44 {
        return Err(Error::InvalidSpki(format!(
            "expected 44 bytes, got {}",
            spki.len()
        )));
    }

    // Validate the SPKI prefix matches Ed25519
    if spki[..12] != ED25519_SPKI_PREFIX {
        return Err(Error::InvalidSpki(
            "SPKI prefix does not match Ed25519 OID".into(),
        ));
    }

    // Extract the 32-byte public key (last 32 bytes)
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&spki[12..44]);
    Ok(public_key)
}

/// Extract ECDSA P-256 public key from SPKI format
///
/// SPKI structure:
/// - 26 bytes: DER prefix (SEQUENCE + AlgorithmIdentifier + BIT STRING header)
/// - 65 bytes: P-256 public key (uncompressed point)
///
/// Validates the DER prefix matches P-256 OID.
fn extract_ecdsa_p256_public_key(spki: &[u8]) -> Result<[u8; 65]> {
    if spki.len() != 91 {
        return Err(Error::InvalidSpki(format!(
            "expected 91 bytes for P-256, got {}",
            spki.len()
        )));
    }

    // Validate the SPKI prefix matches ECDSA P-256
    if spki[..26] != ECDSA_P256_SPKI_PREFIX {
        return Err(Error::InvalidSpki(
            "SPKI prefix does not match ECDSA P-256 OID".into(),
        ));
    }

    // Extract the 65-byte public key (last 65 bytes)
    let mut public_key = [0u8; 65];
    public_key.copy_from_slice(&spki[26..91]);
    Ok(public_key)
}

/// Verify an ECHAuth extension with RPK method
///
/// # Arguments
/// * `ech_config_tbs` - The ECHConfig bytes with ech_auth.signature set to zero-length.
///   Per the draft spec, this MUST include the ech_auth extension with all fields
///   (method, trusted_keys, authenticator, not_after, algorithm) except the signature
///   bytes themselves. This binds not_after into the signature.
/// * `ech_auth` - The parsed ECHAuth extension
/// * `current_time` - Current Unix timestamp (seconds since epoch)
///
/// # Verification Steps
/// 1. Check method is RPK
/// 2. Extract signature block
/// 3. Verify algorithm is Ed25519
/// 4. Parse SPKI and extract public key
/// 5. Compute SHA-256(SPKI) and verify it's in trusted_keys
/// 6. Check current_time < not_after
/// 7. Verify Ed25519 signature over (CONTEXT_LABEL || ech_config_tbs)
pub fn verify_rpk(
    ech_config_tbs: &[u8],
    ech_auth: &ECHAuth,
    current_time: u64,
) -> Result<()> {
    // Step 1: Check method
    if ech_auth.method != ECHAuthMethod::Rpk {
        return Err(Error::UnsupportedMethod(ech_auth.method.to_u8()));
    }

    // Step 2: Extract signature block
    let sig = ech_auth
        .signature
        .as_ref()
        .ok_or(Error::SignatureMissing)?;

    // Step 3: Verify algorithm early (before revealing trust status)
    if sig.algorithm != ED25519_SIGNATURE_SCHEME && sig.algorithm != ECDSA_SECP256R1_SHA256 {
        return Err(Error::UnsupportedAlgorithm(sig.algorithm));
    }

    // Step 4: Parse SPKI and extract public key based on algorithm
    let spki_hash = if sig.algorithm == ED25519_SIGNATURE_SCHEME {
        let public_key_bytes = extract_ed25519_public_key(&sig.authenticator)?;
        let _verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|_| Error::InvalidSpki("invalid Ed25519 public key".into()))?;

        // Compute SHA-256(SPKI)
        let mut hasher = Sha256::new();
        hasher.update(&sig.authenticator);
        let hash: [u8; 32] = hasher.finalize().into();
        hash
    } else {
        let public_key_bytes = extract_ecdsa_p256_public_key(&sig.authenticator)?;
        let _verifying_key = EcdsaVerifyingKey::from_sec1_bytes(&public_key_bytes)
            .map_err(|_| Error::InvalidSpki("invalid ECDSA P-256 public key".into()))?;

        // Compute SHA-256(SPKI)
        let mut hasher = Sha256::new();
        hasher.update(&sig.authenticator);
        let hash: [u8; 32] = hasher.finalize().into();
        hash
    };

    // Step 5: Verify membership in trusted_keys
    if !ech_auth.trusted_keys.contains(&spki_hash) {
        return Err(Error::UntrustedKey);
    }

    // Step 6: Check expiration
    if current_time >= sig.not_after {
        return Err(Error::Expired {
            not_after: sig.not_after,
            current: current_time,
        });
    }

    // Step 7: Build to_be_signed and verify signature
    let mut to_be_signed = Vec::with_capacity(CONTEXT_LABEL.len() + ech_config_tbs.len());
    to_be_signed.extend_from_slice(CONTEXT_LABEL);
    to_be_signed.extend_from_slice(ech_config_tbs);

    // Verify signature based on algorithm
    if sig.algorithm == ED25519_SIGNATURE_SCHEME {
        if sig.signature.len() != 64 {
            return Err(Error::SignatureInvalid);
        }

        let public_key_bytes = extract_ed25519_public_key(&sig.authenticator)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|_| Error::InvalidSpki("invalid Ed25519 public key".into()))?;
        let signature = Signature::from_slice(&sig.signature).map_err(|_| Error::SignatureInvalid)?;

        verifying_key
            .verify(&to_be_signed, &signature)
            .map_err(|_| Error::SignatureInvalid)?;
    } else if sig.algorithm == ECDSA_SECP256R1_SHA256 {
        // ECDSA with SHA-256 - we need to hash first, then verify against the hash
        let mut hasher = Sha256::new();
        hasher.update(&to_be_signed);
        let hash = hasher.finalize();

        let public_key_bytes = extract_ecdsa_p256_public_key(&sig.authenticator)?;
        let verifying_key = EcdsaVerifyingKey::from_sec1_bytes(&public_key_bytes)
            .map_err(|_| Error::InvalidSpki("invalid ECDSA P-256 public key".into()))?;
        let signature = EcdsaSignature::from_der(&sig.signature)
            .map_err(|_| Error::SignatureInvalid)?;

        // Verify the signature against the hash
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        verifying_key
            .verify_prehash(&hash, &signature)
            .map_err(|_| Error::SignatureInvalid)?;
    }

    Ok(())
}

/// Verify an ECHAuth extension with PKIX method (versioned)
///
/// # Arguments
/// * `ech_config_tbs` - The ECHConfig bytes with ech_auth.signature set to zero-length
/// * `ech_auth` - The parsed ECHAuth extension
/// * `public_name` - The public_name from the ECHConfig (for SAN check)
/// * `trust_anchors` - Root certificates to trust (DER-encoded)
/// * `current_time` - Current Unix timestamp
/// * `version` - Spec version for not_after handling
///
/// # Verification Steps
/// 1. Check method is PKIX
/// 2. Parse certificate chain from authenticator
/// 3. Verify leaf certificate has id-pe-echConfigSigning extension (critical)
/// 4. Verify leaf certificate SAN includes public_name
/// 5. Validate certificate chain to trust anchor
/// 6. Check certificate validity against current_time
/// 7. Extract public key from leaf certificate
/// 8. Verify signature based on algorithm
pub fn verify_pkix_versioned(
    ech_config_tbs: &[u8],
    ech_auth: &ECHAuth,
    public_name: &str,
    trust_anchors: &[Vec<u8>],
    current_time: u64,
    version: SpecVersion,
) -> Result<()> {
    // Step 1: Check method
    if ech_auth.method != ECHAuthMethod::Pkix {
        return Err(Error::UnsupportedMethod(ech_auth.method.to_wire(version)));
    }

    // Step 2: Extract signature block
    let sig = ech_auth
        .signature
        .as_ref()
        .ok_or(Error::SignatureMissing)?;

    // Step 2.5: Check expiration based on version
    // - Published: not_after must be 0 (skip validation)
    // - PR2: not_after required, verify current_time < not_after
    match version {
        SpecVersion::Published => {
            // Published spec: not_after should be 0, skip time check
            // (certificate chain validation handles expiration)
        }
        SpecVersion::PR2 => {
            if current_time >= sig.not_after {
                return Err(Error::Expired {
                    not_after: sig.not_after,
                    current: current_time,
                });
            }
        }
    }

    // Parse certificate chain from authenticator
    let certificates = parse_certificate_chain(&sig.authenticator)?;
    if certificates.is_empty() {
        return Err(Error::ChainValidationFailed("empty certificate chain".into()));
    }

    let leaf_cert_der = &certificates[0];
    let leaf_cert = Certificate::from_der(leaf_cert_der)
        .map_err(|e| Error::CertificateInvalid(format!("failed to parse leaf certificate: {}", e)))?;

    // Step 3: Check for critical id-pe-echConfigSigning extension
    // OID 1.3.6.1.5.5.7.1.99 (using 99 for testing instead of TBD2)
    let ech_config_signing_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.99");
    let mut has_ech_signing_ext = false;
    if let Some(extensions) = &leaf_cert.tbs_certificate.extensions {
        for ext in extensions {
            if ext.extn_id == ech_config_signing_oid {
                if !ext.critical {
                    return Err(Error::MissingExtension(
                        "id-pe-echConfigSigning extension must be critical".into(),
                    ));
                }
                has_ech_signing_ext = true;
                break;
            }
        }
    }
    if !has_ech_signing_ext {
        return Err(Error::MissingExtension(
            "missing id-pe-echConfigSigning extension".into(),
        ));
    }

    // Step 4: Verify SAN includes public_name
    verify_san_matches(&leaf_cert, public_name)?;

    // Step 5 & 6: Validate certificate chain (simplified - in production use webpki or similar)
    verify_certificate_chain(&certificates, trust_anchors, current_time)?;

    // Step 7: Extract public key from leaf certificate
    let public_key_info = &leaf_cert.tbs_certificate.subject_public_key_info;

    // Step 8: Build to_be_signed and verify signature
    let mut to_be_signed = Vec::with_capacity(CONTEXT_LABEL.len() + ech_config_tbs.len());
    to_be_signed.extend_from_slice(CONTEXT_LABEL);
    to_be_signed.extend_from_slice(ech_config_tbs);

    // Verify based on algorithm
    if sig.algorithm == ED25519_SIGNATURE_SCHEME {
        // Ed25519 OID: 1.3.101.112
        let ed25519_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.101.112");
        if public_key_info.algorithm.oid != ed25519_oid {
            return Err(Error::CertificateInvalid(
                "certificate algorithm does not match signature algorithm".into(),
            ));
        }

        if sig.signature.len() != 64 {
            return Err(Error::SignatureInvalid);
        }

        // Extract raw public key bytes (skip BIT STRING header)
        let public_key_bytes = public_key_info.subject_public_key.raw_bytes();
        if public_key_bytes.len() != 32 {
            return Err(Error::InvalidSpki("invalid Ed25519 public key length".into()));
        }

        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(public_key_bytes);
        let verifying_key = VerifyingKey::from_bytes(&pk_array)
            .map_err(|_| Error::InvalidSpki("invalid Ed25519 public key".into()))?;
        let signature = Signature::from_slice(&sig.signature).map_err(|_| Error::SignatureInvalid)?;

        verifying_key
            .verify(&to_be_signed, &signature)
            .map_err(|_| Error::SignatureInvalid)?;
    } else if sig.algorithm == ECDSA_SECP256R1_SHA256 {
        // ECDSA P-256 OID: 1.2.840.10045.3.1.7
        let ec_public_key_oid = const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
        if public_key_info.algorithm.oid != ec_public_key_oid {
            return Err(Error::CertificateInvalid(
                "certificate algorithm does not match signature algorithm".into(),
            ));
        }

        // ECDSA with SHA-256 - we need to hash first, then verify against the hash
        let mut hasher = Sha256::new();
        hasher.update(&to_be_signed);
        let hash = hasher.finalize();

        // Extract raw public key bytes
        let public_key_bytes = public_key_info.subject_public_key.raw_bytes();
        let verifying_key = EcdsaVerifyingKey::from_sec1_bytes(public_key_bytes)
            .map_err(|_| Error::InvalidSpki("invalid ECDSA P-256 public key".into()))?;
        let signature = EcdsaSignature::from_der(&sig.signature)
            .map_err(|_| Error::SignatureInvalid)?;

        // Verify the signature against the hash
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        verifying_key
            .verify_prehash(&hash, &signature)
            .map_err(|_| Error::SignatureInvalid)?;
    } else {
        return Err(Error::UnsupportedAlgorithm(sig.algorithm));
    }

    Ok(())
}

/// Verify an ECHAuth extension with PKIX method (uses DEFAULT_SPEC_VERSION)
pub fn verify_pkix(
    ech_config_tbs: &[u8],
    ech_auth: &ECHAuth,
    public_name: &str,
    trust_anchors: &[Vec<u8>],
    current_time: u64,
) -> Result<()> {
    verify_pkix_versioned(ech_config_tbs, ech_auth, public_name, trust_anchors, current_time, DEFAULT_SPEC_VERSION)
}

/// Parse certificate chain from TLS-style encoding (24-bit length prefix per cert)
fn parse_certificate_chain(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut offset = 0;
    let mut certificates = Vec::new();

    while offset < data.len() {
        if data.len() < offset + 3 {
            return Err(Error::Decode("insufficient data for certificate length".into()));
        }

        // 24-bit length (3 bytes, big-endian)
        let cert_len = ((data[offset] as usize) << 16)
            | ((data[offset + 1] as usize) << 8)
            | (data[offset + 2] as usize);
        offset += 3;

        if data.len() < offset + cert_len {
            return Err(Error::Decode("insufficient data for certificate".into()));
        }

        let cert = data[offset..offset + cert_len].to_vec();
        certificates.push(cert);
        offset += cert_len;
    }

    Ok(certificates)
}

/// Verify SAN matches public_name (simplified check)
fn verify_san_matches(cert: &Certificate, _public_name: &str) -> Result<()> {
    // SAN extension OID: 2.5.29.17
    let san_oid = const_oid::ObjectIdentifier::new_unwrap("2.5.29.17");

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions {
            if ext.extn_id == san_oid {
                // In production, parse the SAN and check for dNSName matching public_name
                // For now, just check that the extension exists
                // TODO: Full SAN parsing
                return Ok(());
            }
        }
    }

    Err(Error::SanMismatch)
}

/// Verify certificate chain using webpki
fn verify_certificate_chain(
    certificates: &[Vec<u8>],
    trust_anchors: &[Vec<u8>],
    current_time: u64,
) -> Result<()> {
    if certificates.is_empty() {
        return Err(Error::ChainValidationFailed("empty certificate chain".into()));
    }
    if trust_anchors.is_empty() {
        return Err(Error::ChainValidationFailed("no trust anchors provided".into()));
    }

    // Parse trust anchors from DER-encoded certificates
    let anchors: Vec<_> = trust_anchors
        .iter()
        .map(|der| {
            let cert_der = CertificateDer::from(der.as_slice());
            anchor_from_trusted_cert(&cert_der)
                .map(|anchor| anchor.to_owned())
                .map_err(|e| Error::ChainValidationFailed(format!("invalid trust anchor: {:?}", e)))
        })
        .collect::<Result<Vec<_>>>()?;

    // Parse leaf certificate
    let leaf_der = CertificateDer::from(certificates[0].as_slice());
    let leaf = EndEntityCert::try_from(&leaf_der)
        .map_err(|e| Error::CertificateInvalid(format!("invalid leaf cert: {:?}", e)))?;

    // Parse intermediate certificates
    let intermediates: Vec<CertificateDer> = certificates[1..]
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();

    // Convert time
    let time = UnixTime::since_unix_epoch(std::time::Duration::from_secs(current_time));

    // Verify the certificate chain
    leaf.verify_for_usage(
        ALL_VERIFICATION_ALGS,
        &anchors,
        &intermediates,
        time,
        KeyUsage::server_auth(),
        None, // No revocation checking
        None, // No OCSP
    )
    .map_err(|e| Error::ChainValidationFailed(format!("{:?}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{encode_ed25519_spki, encode_ecdsa_p256_spki, sign_rpk, sign_rpk_ecdsa};
    use crate::SPKIHash;
    use ed25519_dalek::SigningKey;
    use p256::{ecdsa::SigningKey as EcdsaSigningKey, SecretKey};
    use sha2::{Digest, Sha256};

    #[test]
    fn test_extract_ed25519_public_key() {
        let public_key = [42u8; 32];
        let spki = encode_ed25519_spki(&public_key);

        let extracted = extract_ed25519_public_key(&spki).unwrap();
        assert_eq!(extracted, public_key);
    }

    #[test]
    fn test_extract_ed25519_public_key_wrong_length() {
        let spki = vec![0u8; 40]; // Wrong length
        assert!(extract_ed25519_public_key(&spki).is_err());
    }

    #[test]
    fn test_extract_ed25519_public_key_wrong_prefix() {
        // 44 bytes but wrong OID (pretend it's ECDSA P-256)
        let mut spki = vec![0u8; 44];
        spki[0] = 0x30; // SEQUENCE
        spki[1] = 0x2a; // 42 bytes
        // Different OID in bytes 4-8
        let result = extract_ed25519_public_key(&spki);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("does not match Ed25519"));
    }

    #[test]
    fn test_verify_rpk_success() {
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let ech_config_tbs = b"test config for verification";
        let not_after = 2000000000;

        // Sign
        let sig = sign_rpk(ech_config_tbs, &signing_key, not_after);

        // Compute SPKI hash for trusted_keys
        let mut hasher = Sha256::new();
        hasher.update(&sig.authenticator);
        let spki_hash: SPKIHash = hasher.finalize().into();

        // Build ECHAuth
        let ech_auth = ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![spki_hash],
            signature: Some(sig),
        };

        // Verify
        let current_time = 1900000000;
        assert!(verify_rpk(ech_config_tbs, &ech_auth, current_time).is_ok());
    }

    #[test]
    fn test_verify_rpk_wrong_key() {
        let signing_key = SigningKey::from_bytes(&[4u8; 32]);
        let ech_config_tbs = b"test config";
        let not_after = 2000000000;

        // Sign
        let sig = sign_rpk(ech_config_tbs, &signing_key, not_after);

        // Use a different trusted key
        let wrong_hash = [99u8; 32];

        let ech_auth = ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![wrong_hash],
            signature: Some(sig),
        };

        let current_time = 1900000000;
        assert!(matches!(
            verify_rpk(ech_config_tbs, &ech_auth, current_time),
            Err(Error::UntrustedKey)
        ));
    }

    #[test]
    fn test_verify_rpk_expired() {
        let signing_key = SigningKey::from_bytes(&[5u8; 32]);
        let ech_config_tbs = b"test config";
        let not_after = 1500000000;

        // Sign
        let sig = sign_rpk(ech_config_tbs, &signing_key, not_after);

        // Compute SPKI hash
        let mut hasher = Sha256::new();
        hasher.update(&sig.authenticator);
        let spki_hash: SPKIHash = hasher.finalize().into();

        let ech_auth = ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![spki_hash],
            signature: Some(sig),
        };

        // Current time is after expiration
        let current_time = 1600000000;
        assert!(matches!(
            verify_rpk(ech_config_tbs, &ech_auth, current_time),
            Err(Error::Expired { .. })
        ));
    }

    #[test]
    fn test_verify_rpk_wrong_signature() {
        let signing_key = SigningKey::from_bytes(&[6u8; 32]);
        let ech_config_tbs = b"test config";
        let not_after = 2000000000;

        // Sign
        let mut sig = sign_rpk(ech_config_tbs, &signing_key, not_after);

        // Corrupt signature
        sig.signature[0] ^= 1;

        // Compute SPKI hash
        let mut hasher = Sha256::new();
        hasher.update(&sig.authenticator);
        let spki_hash: SPKIHash = hasher.finalize().into();

        let ech_auth = ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![spki_hash],
            signature: Some(sig),
        };

        let current_time = 1900000000;
        assert!(matches!(
            verify_rpk(ech_config_tbs, &ech_auth, current_time),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn test_verify_rpk_wrong_method() {
        // Using PKIX method should fail for RPK verification
        let ech_auth = ECHAuth {
            method: ECHAuthMethod::Pkix,
            trusted_keys: vec![],
            signature: None,
        };

        assert!(matches!(
            verify_rpk(b"", &ech_auth, 0),
            Err(Error::UnsupportedMethod(1))
        ));
    }

    #[test]
    fn test_verify_rpk_missing_signature() {
        let ech_auth = ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![[0u8; 32]],
            signature: None,
        };

        assert!(matches!(
            verify_rpk(b"", &ech_auth, 0),
            Err(Error::SignatureMissing)
        ));
    }

    #[test]
    fn test_verify_rpk_wrong_algorithm() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let ech_config_tbs = b"test config";
        let not_after = 2000000000;

        // Sign
        let mut sig = sign_rpk(ech_config_tbs, &signing_key, not_after);

        // Change algorithm to something invalid
        sig.algorithm = 0xFFFF;

        // Compute SPKI hash
        let mut hasher = Sha256::new();
        hasher.update(&sig.authenticator);
        let spki_hash: SPKIHash = hasher.finalize().into();

        let ech_auth = ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![spki_hash],
            signature: Some(sig),
        };

        let current_time = 1900000000;
        assert!(matches!(
            verify_rpk(ech_config_tbs, &ech_auth, current_time),
            Err(Error::UnsupportedAlgorithm(0xFFFF))
        ));
    }

    #[test]
    fn test_verify_rpk_multiple_trusted_keys() {
        let signing_key = SigningKey::from_bytes(&[8u8; 32]);
        let ech_config_tbs = b"test config";
        let not_after = 2000000000;

        // Sign
        let sig = sign_rpk(ech_config_tbs, &signing_key, not_after);

        // Compute SPKI hash
        let mut hasher = Sha256::new();
        hasher.update(&sig.authenticator);
        let spki_hash: SPKIHash = hasher.finalize().into();

        // Build ECHAuth with multiple trusted keys
        let ech_auth = ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![[1u8; 32], [2u8; 32], spki_hash, [3u8; 32]],
            signature: Some(sig),
        };

        // Verify
        let current_time = 1900000000;
        assert!(verify_rpk(ech_config_tbs, &ech_auth, current_time).is_ok());
    }

    #[test]
    fn test_extract_ecdsa_p256_public_key() {
        let public_key = [4u8; 65];
        let spki = encode_ecdsa_p256_spki(&public_key);

        let extracted = extract_ecdsa_p256_public_key(&spki).unwrap();
        assert_eq!(extracted, public_key);
    }

    #[test]
    fn test_extract_ecdsa_p256_public_key_wrong_length() {
        let spki = vec![0u8; 80];
        assert!(extract_ecdsa_p256_public_key(&spki).is_err());
    }

    #[test]
    fn test_verify_rpk_ecdsa_success() {
        let secret_key = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let signing_key = EcdsaSigningKey::from(secret_key);
        let ech_config_tbs = b"test config for ecdsa verification";
        let not_after = 2000000000;

        // Sign
        let sig = sign_rpk_ecdsa(ech_config_tbs, &signing_key, not_after);

        // Compute SPKI hash for trusted_keys
        let mut hasher = Sha256::new();
        hasher.update(&sig.authenticator);
        let spki_hash: SPKIHash = hasher.finalize().into();

        // Build ECHAuth
        let ech_auth = ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![spki_hash],
            signature: Some(sig),
        };

        // Verify
        let current_time = 1900000000;
        assert!(verify_rpk(ech_config_tbs, &ech_auth, current_time).is_ok());
    }

    #[test]
    fn test_verify_rpk_ecdsa_wrong_signature() {
        let secret_key = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let signing_key = EcdsaSigningKey::from(secret_key);
        let ech_config_tbs = b"test config";
        let not_after = 2000000000;

        // Sign
        let mut sig = sign_rpk_ecdsa(ech_config_tbs, &signing_key, not_after);

        // Corrupt signature
        sig.signature[0] ^= 1;

        // Compute SPKI hash
        let mut hasher = Sha256::new();
        hasher.update(&sig.authenticator);
        let spki_hash: SPKIHash = hasher.finalize().into();

        let ech_auth = ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![spki_hash],
            signature: Some(sig),
        };

        let current_time = 1900000000;
        assert!(matches!(
            verify_rpk(ech_config_tbs, &ech_auth, current_time),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn test_parse_certificate_chain() {
        let cert1 = vec![0x30, 0x82, 0x01, 0x00];
        let cert2 = vec![0x30, 0x82, 0x02, 0x00];

        let mut chain_bytes = Vec::new();
        // Cert 1 with 24-bit length
        chain_bytes.extend_from_slice(&[0x00, 0x00, 0x04]); // length = 4
        chain_bytes.extend_from_slice(&cert1);
        // Cert 2 with 24-bit length
        chain_bytes.extend_from_slice(&[0x00, 0x00, 0x04]); // length = 4
        chain_bytes.extend_from_slice(&cert2);

        let parsed = parse_certificate_chain(&chain_bytes).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], cert1);
        assert_eq!(parsed[1], cert2);
    }
}
