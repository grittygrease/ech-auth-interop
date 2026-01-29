use crate::{ECHAuth, ECHAuthInfo, ECHAuthMethod, ECHAuthRetry, ECHAuthSignature, Error, Result, SpecVersion, DEFAULT_SPEC_VERSION};

impl ECHAuth {
    /// Encode to TLS presentation language format with spec version
    pub fn encode_versioned(&self, version: SpecVersion) -> Vec<u8> {
        let mut buf = Vec::new();

        // method: u8 (version-aware)
        buf.push(self.method.to_wire(version));

        // trusted_keys: u16 length prefix, then N*32 bytes
        let keys_len = self.trusted_keys.len() * 32;
        buf.extend_from_slice(&(keys_len as u16).to_be_bytes());
        for hash in &self.trusted_keys {
            buf.extend_from_slice(hash);
        }

        // signature block (or zero-length if None)
        if let Some(ref sig) = self.signature {
            // authenticator: u16 length prefix + data
            buf.extend_from_slice(&(sig.authenticator.len() as u16).to_be_bytes());
            buf.extend_from_slice(&sig.authenticator);

            // not_after: u64 big-endian
            buf.extend_from_slice(&sig.not_after.to_be_bytes());

            // algorithm: u16 big-endian
            buf.extend_from_slice(&sig.algorithm.to_be_bytes());

            // signature: u16 length prefix + data
            buf.extend_from_slice(&(sig.signature.len() as u16).to_be_bytes());
            buf.extend_from_slice(&sig.signature);
        } else {
            // Zero-length authenticator indicates no signature
            buf.extend_from_slice(&0u16.to_be_bytes());
        }

        buf
    }

    /// Encode to TLS presentation language format (uses DEFAULT_SPEC_VERSION)
    pub fn encode(&self) -> Vec<u8> {
        self.encode_versioned(DEFAULT_SPEC_VERSION)
    }

    /// Decode from TLS presentation language format with spec version
    pub fn decode_versioned(data: &[u8], version: SpecVersion) -> Result<Self> {
        let mut offset = 0;

        // Parse method (version-aware)
        if data.len() < offset + 1 {
            return Err(Error::Decode("insufficient data for method".into()));
        }
        let method = ECHAuthMethod::from_wire(data[offset], version)
            .ok_or_else(|| Error::UnsupportedMethod(data[offset]))?;
        offset += 1;

        // Parse trusted_keys length
        if data.len() < offset + 2 {
            return Err(Error::Decode("insufficient data for trusted_keys length".into()));
        }
        let keys_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        // Parse trusted_keys
        if keys_len % 32 != 0 {
            return Err(Error::Decode(format!(
                "trusted_keys length {} not multiple of 32",
                keys_len
            )));
        }
        if data.len() < offset + keys_len {
            return Err(Error::Decode("insufficient data for trusted_keys".into()));
        }

        let mut trusted_keys = Vec::new();
        for i in 0..(keys_len / 32) {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[offset + i * 32..offset + (i + 1) * 32]);
            trusted_keys.push(hash);
        }
        offset += keys_len;

        // Parse signature block
        if data.len() < offset + 2 {
            return Err(Error::Decode("insufficient data for authenticator length".into()));
        }
        let auth_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let signature = if auth_len == 0 {
            None
        } else {
            if data.len() < offset + auth_len {
                return Err(Error::Decode("insufficient data for authenticator".into()));
            }
            let authenticator = data[offset..offset + auth_len].to_vec();
            offset += auth_len;

            if data.len() < offset + 8 {
                return Err(Error::Decode("insufficient data for not_after".into()));
            }
            let not_after = u64::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            offset += 8;

            if data.len() < offset + 2 {
                return Err(Error::Decode("insufficient data for algorithm".into()));
            }
            let algorithm = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;

            if data.len() < offset + 2 {
                return Err(Error::Decode("insufficient data for signature length".into()));
            }
            let sig_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if data.len() < offset + sig_len {
                return Err(Error::Decode("insufficient data for signature".into()));
            }
            let signature = data[offset..offset + sig_len].to_vec();

            Some(ECHAuthSignature {
                authenticator,
                not_after,
                algorithm,
                signature,
            })
        };

        Ok(ECHAuth {
            method,
            trusted_keys,
            signature,
        })
    }

    /// Decode from TLS presentation language format (uses DEFAULT_SPEC_VERSION)
    pub fn decode(data: &[u8]) -> Result<Self> {
        Self::decode_versioned(data, DEFAULT_SPEC_VERSION)
    }
}

// ============================================================================
// Version Detection
// ============================================================================

/// Heuristically detect the spec version from encoded ECHAuth data.
///
/// This is imperfect and can give wrong results for ambiguous data.
/// Using an explicit version parameter is recommended.
///
/// Detection logic:
/// - method=2: definitely Published (pkix)
/// - method=0: likely PR2 (rpk) but could be Published 'none'
/// - method=1: ambiguous (PR2 pkix vs Published rpk)
///
/// Returns None if the data is too short or clearly invalid.
pub fn detect_version(data: &[u8]) -> Option<SpecVersion> {
    if data.is_empty() {
        return None;
    }

    match data[0] {
        0 => Some(SpecVersion::PR2),    // PR2 rpk (or Published 'none' which we don't support)
        1 => None,                       // Ambiguous: PR2 pkix OR Published rpk
        2 => Some(SpecVersion::Published), // Definitely Published pkix
        _ => None,                       // Invalid method
    }
}

// ============================================================================
// PR #2 Format Codecs
// ============================================================================

impl ECHAuthInfo {
    /// Encode to TLS wire format with spec version
    pub fn encode_versioned(&self, version: SpecVersion) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.method.to_wire(version));

        let keys_len = self.trusted_keys.len() * 32;
        buf.extend_from_slice(&(keys_len as u16).to_be_bytes());
        for hash in &self.trusted_keys {
            buf.extend_from_slice(hash);
        }

        buf
    }

    /// Encode to TLS wire format (uses DEFAULT_SPEC_VERSION)
    pub fn encode(&self) -> Vec<u8> {
        self.encode_versioned(DEFAULT_SPEC_VERSION)
    }

    /// Decode from TLS wire format with spec version
    pub fn decode_versioned(data: &[u8], version: SpecVersion) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::Decode("insufficient data for method".into()));
        }

        let method = ECHAuthMethod::from_wire(data[0], version)
            .ok_or_else(|| Error::UnsupportedMethod(data[0]))?;

        if data.len() < 3 {
            return Err(Error::Decode("insufficient data for trusted_keys length".into()));
        }
        let keys_len = u16::from_be_bytes([data[1], data[2]]) as usize;

        if keys_len % 32 != 0 {
            return Err(Error::Decode("trusted_keys length not multiple of 32".into()));
        }
        if data.len() < 3 + keys_len {
            return Err(Error::Decode("insufficient data for trusted_keys".into()));
        }

        let mut trusted_keys = Vec::new();
        for i in 0..(keys_len / 32) {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[3 + i * 32..3 + (i + 1) * 32]);
            trusted_keys.push(hash);
        }

        Ok(ECHAuthInfo { method, trusted_keys })
    }

    /// Decode from TLS wire format (uses DEFAULT_SPEC_VERSION)
    pub fn decode(data: &[u8]) -> Result<Self> {
        Self::decode_versioned(data, DEFAULT_SPEC_VERSION)
    }
}

impl ECHAuthRetry {
    /// Encode to TLS wire format with spec version
    pub fn encode_versioned(&self, version: SpecVersion) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.method.to_wire(version));
        buf.extend_from_slice(&self.not_after.to_be_bytes());
        buf.extend_from_slice(&(self.authenticator.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.authenticator);
        buf.extend_from_slice(&self.algorithm.to_be_bytes());
        buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Encode to TLS wire format (uses DEFAULT_SPEC_VERSION)
    pub fn encode(&self) -> Vec<u8> {
        self.encode_versioned(DEFAULT_SPEC_VERSION)
    }

    /// Decode from TLS wire format with spec version
    pub fn decode_versioned(data: &[u8], version: SpecVersion) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::Decode("insufficient data".into()));
        }

        let method = ECHAuthMethod::from_wire(data[0], version)
            .ok_or_else(|| Error::UnsupportedMethod(data[0]))?;

        if data.len() < 9 {
            return Err(Error::Decode("insufficient data for not_after".into()));
        }
        let not_after = u64::from_be_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ]);

        if data.len() < 11 {
            return Err(Error::Decode("insufficient data for authenticator length".into()));
        }
        let auth_len = u16::from_be_bytes([data[9], data[10]]) as usize;

        if data.len() < 11 + auth_len {
            return Err(Error::Decode("insufficient data for authenticator".into()));
        }
        let authenticator = data[11..11 + auth_len].to_vec();
        let mut offset = 11 + auth_len;

        if data.len() < offset + 2 {
            return Err(Error::Decode("insufficient data for algorithm".into()));
        }
        let algorithm = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        if data.len() < offset + 2 {
            return Err(Error::Decode("insufficient data for signature length".into()));
        }
        let sig_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + sig_len {
            return Err(Error::Decode("insufficient data for signature".into()));
        }
        let signature = data[offset..offset + sig_len].to_vec();

        Ok(ECHAuthRetry {
            method,
            not_after,
            authenticator,
            algorithm,
            signature,
        })
    }

    /// Decode from TLS wire format (uses DEFAULT_SPEC_VERSION)
    pub fn decode(data: &[u8]) -> Result<Self> {
        Self::decode_versioned(data, DEFAULT_SPEC_VERSION)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ED25519_SIGNATURE_SCHEME;

    #[test]
    fn test_encode_decode_no_signature() {
        let auth = ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![[0u8; 32], [1u8; 32]],
            signature: None,
        };

        let encoded = auth.encode();
        let decoded = ECHAuth::decode(&encoded).unwrap();
        assert_eq!(auth, decoded);
    }

    #[test]
    fn test_encode_decode_with_signature() {
        let auth = ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![[42u8; 32]],
            signature: Some(ECHAuthSignature {
                authenticator: vec![1, 2, 3, 4],
                not_after: 1234567890,
                algorithm: ED25519_SIGNATURE_SCHEME,
                signature: vec![5, 6, 7, 8],
            }),
        };

        let encoded = auth.encode();
        let decoded = ECHAuth::decode(&encoded).unwrap();
        assert_eq!(auth, decoded);
    }

    #[test]
    fn test_authinfo_roundtrip() {
        let info = ECHAuthInfo {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![[42u8; 32]],
        };

        let encoded = info.encode();
        let decoded = ECHAuthInfo::decode(&encoded).unwrap();
        assert_eq!(info, decoded);
    }

    #[test]
    fn test_retry_roundtrip() {
        let retry = ECHAuthRetry {
            method: ECHAuthMethod::Rpk,
            not_after: 1234567890,
            authenticator: vec![1, 2, 3],
            algorithm: ED25519_SIGNATURE_SCHEME,
            signature: vec![4, 5, 6],
        };

        let encoded = retry.encode();
        let decoded = ECHAuthRetry::decode(&encoded).unwrap();
        assert_eq!(retry, decoded);
    }

    #[test]
    fn test_decode_invalid_method() {
        let data = [255u8, 0, 0, 0, 0];
        assert!(matches!(
            ECHAuth::decode(&data),
            Err(Error::UnsupportedMethod(255))
        ));
    }

    #[test]
    fn test_versioned_encode_decode_pr2() {
        let auth = ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![[42u8; 32]],
            signature: None,
        };

        let encoded = auth.encode_versioned(SpecVersion::PR2);
        // PR2: rpk=0
        assert_eq!(encoded[0], 0);

        let decoded = ECHAuth::decode_versioned(&encoded, SpecVersion::PR2).unwrap();
        assert_eq!(auth, decoded);
    }

    #[test]
    fn test_versioned_encode_decode_published() {
        let auth = ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![[42u8; 32]],
            signature: None,
        };

        let encoded = auth.encode_versioned(SpecVersion::Published);
        // Published: rpk=1
        assert_eq!(encoded[0], 1);

        let decoded = ECHAuth::decode_versioned(&encoded, SpecVersion::Published).unwrap();
        assert_eq!(auth, decoded);
    }

    #[test]
    fn test_versioned_pkix_method() {
        let auth = ECHAuth {
            method: ECHAuthMethod::Pkix,
            trusted_keys: vec![],
            signature: None,
        };

        // PR2: pkix=1
        let encoded_pr2 = auth.encode_versioned(SpecVersion::PR2);
        assert_eq!(encoded_pr2[0], 1);

        // Published: pkix=2
        let encoded_pub = auth.encode_versioned(SpecVersion::Published);
        assert_eq!(encoded_pub[0], 2);
    }

    #[test]
    fn test_cross_version_mismatch() {
        // Encode with Published (rpk=1), decode with PR2 (1=pkix)
        let auth = ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![[42u8; 32]],
            signature: None,
        };

        let encoded = auth.encode_versioned(SpecVersion::Published);
        // Method byte is 1 (Published rpk)
        assert_eq!(encoded[0], 1);

        // Decode with PR2: method 1 = Pkix (wrong!)
        let decoded = ECHAuth::decode_versioned(&encoded, SpecVersion::PR2).unwrap();
        assert_eq!(decoded.method, ECHAuthMethod::Pkix);
        assert_ne!(decoded.method, auth.method);
    }
}
