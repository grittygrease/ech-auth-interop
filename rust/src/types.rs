/// TLS SignatureScheme for Ed25519 (RFC 8446)
pub const ED25519_SIGNATURE_SCHEME: u16 = 0x0807;

/// TLS SignatureScheme for ECDSA P-256 SHA-256 (RFC 8446)
pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;

/// ECH authentication method enumeration
/// PR #2 changes: rpk=0, pkix=1 (was: none=0, rpk=1, pkix=2)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ECHAuthMethod {
    Rpk = 0,
    Pkix = 1,
}

impl ECHAuthMethod {
    /// Parse from wire format byte
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Rpk),
            1 => Some(Self::Pkix),
            _ => None,
        }
    }

    /// Convert to wire format byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// SHA-256 hash of DER-encoded SPKI (32 bytes)
pub type SPKIHash = [u8; 32];

/// ECH authentication signature block (used in ECHAuth combined format)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECHAuthSignature {
    /// The authenticator (SPKI for RPK, certificate chain for PKIX)
    pub authenticator: Vec<u8>,
    /// Expiration timestamp (Unix epoch seconds)
    pub not_after: u64,
    /// TLS SignatureScheme identifier
    pub algorithm: u16,
    /// The signature bytes
    pub signature: Vec<u8>,
}

/// ECH authentication extension (combined format for interop)
/// This is the legacy format used before PR #2 split
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECHAuth {
    /// Authentication method
    pub method: ECHAuthMethod,
    /// List of trusted SPKI hashes
    pub trusted_keys: Vec<SPKIHash>,
    /// Optional signature block
    pub signature: Option<ECHAuthSignature>,
}

// ============================================================================
// PR #2 Wire Format Types (extension split)
// ============================================================================

/// ECH authentication info (ech_authinfo) - for initial ECHConfig in DNS
/// Contains only policy, no signature. This is the PR #2 format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECHAuthInfo {
    /// Authentication method
    pub method: ECHAuthMethod,
    /// List of trusted SPKI hashes (RPK only)
    pub trusted_keys: Vec<SPKIHash>,
}

/// ECH authentication extension (ech_auth) - for retry configs in TLS
/// Contains the full signature. This is the PR #2 format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECHAuthRetry {
    /// Authentication method
    pub method: ECHAuthMethod,
    /// Expiration timestamp (Unix epoch seconds)
    pub not_after: u64,
    /// The authenticator (SPKI for RPK, certificate chain for PKIX)
    pub authenticator: Vec<u8>,
    /// TLS SignatureScheme identifier
    pub algorithm: u16,
    /// The signature bytes
    pub signature: Vec<u8>,
}

impl ECHAuthRetry {
    /// Compute SPKI hash from authenticator (for RPK verification)
    pub fn spki_hash(&self) -> SPKIHash {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.authenticator);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

impl ECHAuth {
    /// Convert to PR #2 split format
    pub fn to_pr2(&self) -> (ECHAuthInfo, Option<ECHAuthRetry>) {
        let info = ECHAuthInfo {
            method: self.method,
            trusted_keys: self.trusted_keys.clone(),
        };

        let retry = self.signature.as_ref().map(|sig| ECHAuthRetry {
            method: self.method,
            not_after: sig.not_after,
            authenticator: sig.authenticator.clone(),
            algorithm: sig.algorithm,
            signature: sig.signature.clone(),
        });

        (info, retry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_roundtrip() {
        assert_eq!(ECHAuthMethod::from_u8(0), Some(ECHAuthMethod::Rpk));
        assert_eq!(ECHAuthMethod::from_u8(1), Some(ECHAuthMethod::Pkix));
        assert_eq!(ECHAuthMethod::from_u8(2), None);

        assert_eq!(ECHAuthMethod::Rpk.to_u8(), 0);
        assert_eq!(ECHAuthMethod::Pkix.to_u8(), 1);
    }

    #[test]
    fn test_to_pr2() {
        let auth = ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![[42u8; 32]],
            signature: Some(ECHAuthSignature {
                authenticator: vec![1, 2, 3],
                not_after: 1234567890,
                algorithm: ED25519_SIGNATURE_SCHEME,
                signature: vec![4, 5, 6],
            }),
        };

        let (info, retry) = auth.to_pr2();
        assert_eq!(info.method, ECHAuthMethod::Rpk);
        assert_eq!(info.trusted_keys.len(), 1);

        let retry = retry.unwrap();
        assert_eq!(retry.not_after, 1234567890);
        assert_eq!(retry.authenticator, vec![1, 2, 3]);
    }
}
