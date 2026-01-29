use crate::{ECHAuth, ECHAuthMethod, ECHAuthSignature, Error, Result};

impl ECHAuth {
    /// Encode to TLS presentation language format
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // method: u8
        buf.push(self.method.to_u8());

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
            // Zero-length signature block (u16 len = 0)
            buf.extend_from_slice(&0u16.to_be_bytes());
        }

        buf
    }

    /// Decode from TLS presentation language format
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut offset = 0;

        // Parse method
        if data.len() < offset + 1 {
            return Err(Error::Decode("insufficient data for method".into()));
        }
        let method = ECHAuthMethod::from_u8(data[offset])
            .ok_or_else(|| Error::UnsupportedMethod(data[offset]))?;
        offset += 1;

        // Parse trusted_keys length
        if data.len() < offset + 2 {
            return Err(Error::Decode("insufficient data for trusted_keys length".into()));
        }
        let keys_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        // Parse trusted_keys
        if !keys_len.is_multiple_of(32) {
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
        // First check if there's a signature authenticator length field
        if data.len() < offset + 2 {
            return Err(Error::Decode("insufficient data for signature length".into()));
        }
        let auth_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let signature = if auth_len == 0 {
            // No signature block
            None
        } else {
            // Parse authenticator
            if data.len() < offset + auth_len {
                return Err(Error::Decode("insufficient data for authenticator".into()));
            }
            let authenticator = data[offset..offset + auth_len].to_vec();
            offset += auth_len;

            // Parse not_after
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

            // Parse algorithm
            if data.len() < offset + 2 {
                return Err(Error::Decode("insufficient data for algorithm".into()));
            }
            let algorithm = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;

            // Parse signature
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ED25519_SIGNATURE_SCHEME;

    #[test]
    fn test_encode_decode_no_signature() {
        let auth = ECHAuth {
            method: ECHAuthMethod::None,
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
    fn test_decode_empty() {
        assert!(ECHAuth::decode(&[]).is_err());
    }

    #[test]
    fn test_decode_invalid_method() {
        let data = [255u8, 0, 0, 0, 0]; // Invalid method = 255
        assert!(matches!(
            ECHAuth::decode(&data),
            Err(Error::UnsupportedMethod(255))
        ));
    }

    #[test]
    fn test_decode_wrong_keys_length() {
        let data = [
            1u8,  // method = Rpk
            0, 5, // keys_len = 5 (not multiple of 32)
        ];
        assert!(matches!(
            ECHAuth::decode(&data),
            Err(Error::Decode(_))
        ));
    }

    #[test]
    fn test_roundtrip_empty_keys() {
        let auth = ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![],
            signature: None,
        };

        let encoded = auth.encode();
        let decoded = ECHAuth::decode(&encoded).unwrap();

        assert_eq!(auth, decoded);
    }
}
