/// TLS SignatureScheme for Ed25519 (RFC 8446)
pub const ED25519_SIGNATURE_SCHEME: u16 = 0x0807;

/// TLS SignatureScheme for ECDSA P-256 SHA-256 (RFC 8446)
pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;

/// ECH authentication method enumeration
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ECHAuthMethod {
    None = 0,
    Rpk = 1,
    Pkix = 2,
}

impl ECHAuthMethod {
    /// Parse from wire format byte
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Rpk),
            2 => Some(Self::Pkix),
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

/// ECH authentication signature block
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

/// ECH authentication extension
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECHAuth {
    /// Authentication method
    pub method: ECHAuthMethod,
    /// List of trusted SPKI hashes
    pub trusted_keys: Vec<SPKIHash>,
    /// Optional signature block
    pub signature: Option<ECHAuthSignature>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_roundtrip() {
        assert_eq!(ECHAuthMethod::from_u8(0), Some(ECHAuthMethod::None));
        assert_eq!(ECHAuthMethod::from_u8(1), Some(ECHAuthMethod::Rpk));
        assert_eq!(ECHAuthMethod::from_u8(2), Some(ECHAuthMethod::Pkix));
        assert_eq!(ECHAuthMethod::from_u8(3), None);

        assert_eq!(ECHAuthMethod::None.to_u8(), 0);
        assert_eq!(ECHAuthMethod::Rpk.to_u8(), 1);
        assert_eq!(ECHAuthMethod::Pkix.to_u8(), 2);
    }
}
