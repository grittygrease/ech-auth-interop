//! ECHConfig structure and builder
//!
//! This module provides the core ECHConfig structure for representing ECH
//! configurations, along with a builder for constructing them and functions
//! for encoding/decoding.
//!
//! # Main Types
//!
//! - [`ECHConfig`] - The ECH configuration structure
//! - [`ECHConfigBuilder`] - Builder for creating ECHConfigs
//! - [`HpkeSymmetricCipherSuite`] - HPKE cipher suite (KDF + AEAD)
//!
//! # Constants
//!
//! The module provides constants for HPKE algorithms:
//! - KEMs: [`DHKEM_X25519_SHA256`], [`DHKEM_P256_SHA256`]
//! - KDFs: [`HKDF_SHA256`], [`HKDF_SHA384`]
//! - AEADs: [`AES_128_GCM`], [`AES_256_GCM`], [`CHACHA20_POLY1305`]
//!
//! # Example
//!
//! ```
//! # use ech_auth::*;
//! let config = ECHConfigBuilder::new()
//!     .config_id(1)
//!     .kem_id(DHKEM_X25519_SHA256)
//!     .public_key(vec![0u8; 32])
//!     .add_cipher_suite(HKDF_SHA256, AES_128_GCM)
//!     .public_name("example.com")
//!     .build()
//!     .unwrap();
//!
//! // Encode and decode
//! let bytes = config.encode();
//! let decoded = ECHConfig::decode(&bytes).unwrap();
//! assert_eq!(config, decoded);
//! ```

use crate::{ECHAuth, Error, Result};

/// ECH version for draft-ietf-tls-esni
pub const ECH_VERSION: u16 = 0xfe0d;

/// HPKE KEMs
pub const DHKEM_X25519_SHA256: u16 = 0x0020;
pub const DHKEM_P256_SHA256: u16 = 0x0010;

/// HPKE KDFs
pub const HKDF_SHA256: u16 = 0x0001;
pub const HKDF_SHA384: u16 = 0x0002;

/// HPKE AEADs
pub const AES_128_GCM: u16 = 0x0001;
pub const AES_256_GCM: u16 = 0x0002;
pub const CHACHA20_POLY1305: u16 = 0x0003;

/// ECHConfig extension type for ech_auth (per draft-sullivan-tls-signed-ech-updates)
pub const ECH_AUTH_EXTENSION_TYPE: u16 = 0xfe0d;

/// HPKE symmetric cipher suite (KDF + AEAD)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HpkeSymmetricCipherSuite {
    pub kdf_id: u16,
    pub aead_id: u16,
}

/// ECHConfig structure per draft-ietf-tls-esni
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECHConfig {
    pub version: u16,
    pub config_id: u8,
    pub kem_id: u16,
    pub public_key: Vec<u8>,
    pub cipher_suites: Vec<HpkeSymmetricCipherSuite>,
    pub maximum_name_length: u8,
    pub public_name: String,
    pub extensions: Vec<u8>,
}

impl ECHConfig {
    /// Encode ECHConfig to wire format
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // version: u16
        buf.extend_from_slice(&self.version.to_be_bytes());

        // Reserve space for length (u16)
        let length_offset = buf.len();
        buf.extend_from_slice(&[0u8; 2]);

        let contents_start = buf.len();

        // ECHConfigContents:
        // HpkeKeyConfig:
        // config_id: u8
        buf.push(self.config_id);

        // kem_id: u16
        buf.extend_from_slice(&self.kem_id.to_be_bytes());

        // public_key: opaque<1..2^16-1>
        buf.extend_from_slice(&(self.public_key.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.public_key);

        // cipher_suites: HpkeSymmetricCipherSuite<4..2^16-4>
        let suites_len = self.cipher_suites.len() * 4;
        buf.extend_from_slice(&(suites_len as u16).to_be_bytes());
        for suite in &self.cipher_suites {
            buf.extend_from_slice(&suite.kdf_id.to_be_bytes());
            buf.extend_from_slice(&suite.aead_id.to_be_bytes());
        }

        // maximum_name_length: u8
        buf.push(self.maximum_name_length);

        // public_name: opaque<1..255>
        let name_bytes = self.public_name.as_bytes();
        buf.push(name_bytes.len() as u8);
        buf.extend_from_slice(name_bytes);

        // extensions: opaque<0..2^16-1>
        buf.extend_from_slice(&(self.extensions.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.extensions);

        // Write length field
        let contents_len = buf.len() - contents_start;
        buf[length_offset..length_offset + 2].copy_from_slice(&(contents_len as u16).to_be_bytes());

        buf
    }

    /// Decode ECHConfig from wire format
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut offset = 0;

        // version: u16
        if data.len() < offset + 2 {
            return Err(Error::Decode("insufficient data for version".into()));
        }
        let version = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // length: u16
        if data.len() < offset + 2 {
            return Err(Error::Decode("insufficient data for length".into()));
        }
        let length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        // Verify we have enough data
        if data.len() < offset + length {
            return Err(Error::Decode("insufficient data for contents".into()));
        }

        // config_id: u8
        let config_id = data[offset];
        offset += 1;

        // kem_id: u16
        if data.len() < offset + 2 {
            return Err(Error::Decode("insufficient data for kem_id".into()));
        }
        let kem_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // public_key: opaque<1..2^16-1>
        if data.len() < offset + 2 {
            return Err(Error::Decode(
                "insufficient data for public_key length".into(),
            ));
        }
        let pk_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + pk_len {
            return Err(Error::Decode("insufficient data for public_key".into()));
        }
        let public_key = data[offset..offset + pk_len].to_vec();
        offset += pk_len;

        // cipher_suites: HpkeSymmetricCipherSuite<4..2^16-4>
        if data.len() < offset + 2 {
            return Err(Error::Decode(
                "insufficient data for cipher_suites length".into(),
            ));
        }
        let suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if suites_len < 4 || !suites_len.is_multiple_of(4) {
            return Err(Error::Decode(format!(
                "invalid cipher_suites length: {}",
                suites_len
            )));
        }

        if data.len() < offset + suites_len {
            return Err(Error::Decode("insufficient data for cipher_suites".into()));
        }

        let mut cipher_suites = Vec::new();
        for i in 0..(suites_len / 4) {
            let kdf_id = u16::from_be_bytes([data[offset + i * 4], data[offset + i * 4 + 1]]);
            let aead_id = u16::from_be_bytes([data[offset + i * 4 + 2], data[offset + i * 4 + 3]]);
            cipher_suites.push(HpkeSymmetricCipherSuite { kdf_id, aead_id });
        }
        offset += suites_len;

        // maximum_name_length: u8
        if data.len() < offset + 1 {
            return Err(Error::Decode(
                "insufficient data for maximum_name_length".into(),
            ));
        }
        let maximum_name_length = data[offset];
        offset += 1;

        // public_name: opaque<1..255>
        if data.len() < offset + 1 {
            return Err(Error::Decode(
                "insufficient data for public_name length".into(),
            ));
        }
        let name_len = data[offset] as usize;
        offset += 1;

        if data.len() < offset + name_len {
            return Err(Error::Decode("insufficient data for public_name".into()));
        }
        let public_name = String::from_utf8(data[offset..offset + name_len].to_vec())
            .map_err(|e| Error::Decode(format!("invalid UTF-8 in public_name: {}", e)))?;
        offset += name_len;

        // extensions: opaque<0..2^16-1>
        if data.len() < offset + 2 {
            return Err(Error::Decode(
                "insufficient data for extensions length".into(),
            ));
        }
        let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + ext_len {
            return Err(Error::Decode("insufficient data for extensions".into()));
        }
        let extensions = data[offset..offset + ext_len].to_vec();

        // COMPLIANCE: Validate that if ech_auth extension is present, it MUST be last (Section 5.1)
        validate_extension_ordering(&extensions)?;

        Ok(ECHConfig {
            version,
            config_id,
            kem_id,
            public_key,
            cipher_suites,
            maximum_name_length,
            public_name,
            extensions,
        })
    }

    /// Encode ECHConfig for signing (with ech_auth extension, signature field zeroed)
    pub fn encode_tbs(&self, ech_auth: &ECHAuth) -> Vec<u8> {
        // Create a copy with the signature zeroed
        let mut ech_auth_tbs = ech_auth.clone();
        if let Some(ref mut sig) = ech_auth_tbs.signature {
            sig.signature = Vec::new();
        }

        // Build extension with ech_auth
        let ech_auth_bytes = ech_auth_tbs.encode();
        let mut extensions = Vec::new();

        // extension_type: u16
        extensions.extend_from_slice(&ECH_AUTH_EXTENSION_TYPE.to_be_bytes());

        // extension_data: opaque<0..2^16-1>
        extensions.extend_from_slice(&(ech_auth_bytes.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ech_auth_bytes);

        // Create ECHConfig with this extension
        let mut config_tbs = self.clone();
        config_tbs.extensions = extensions;

        config_tbs.encode()
    }

    /// Add ech_auth extension and return full encoded config
    pub fn with_ech_auth(&self, ech_auth: &ECHAuth) -> Vec<u8> {
        let ech_auth_bytes = ech_auth.encode();
        let mut extensions = Vec::new();

        // extension_type: u16
        extensions.extend_from_slice(&ECH_AUTH_EXTENSION_TYPE.to_be_bytes());

        // extension_data: opaque<0..2^16-1>
        extensions.extend_from_slice(&(ech_auth_bytes.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ech_auth_bytes);

        // Create ECHConfig with this extension
        let mut config = self.clone();
        config.extensions = extensions;

        config.encode()
    }

    /// Extract ech_auth extension from config extensions
    ///
    /// Parses the raw extension bytes to find and decode the ech_auth
    /// extension (type 0xfe0d).
    ///
    /// Returns `None` if no ech_auth extension is present (legacy
    /// unsigned config).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use ech_auth::*;
    /// # fn main() -> Result<()> {
    /// # let bytes = &[0u8; 100];
    /// let config = ECHConfig::decode(bytes)?;
    ///
    /// if let Some(auth) = config.extract_ech_auth()? {
    ///     // Config has authentication
    ///     println!("Method: {:?}", auth.method);
    ///     if let Some(sig) = &auth.signature {
    ///         println!("Expires: {}", sig.not_after);
    ///     }
    /// } else {
    ///     // Legacy unsigned config
    ///     println!("No authentication present");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the extension data is malformed or cannot
    /// be parsed as a valid ECHAuth structure.
    pub fn extract_ech_auth(&self) -> Result<Option<ECHAuth>> {
        // Parse TLV extensions
        let mut offset = 0;
        let ext_data = &self.extensions;

        while offset + 4 <= ext_data.len() {
            if ext_data.len() < offset + 2 {
                return Err(Error::Decode(
                    "malformed extension: insufficient data for type".into(),
                ));
            }
            let ext_type = u16::from_be_bytes([ext_data[offset], ext_data[offset + 1]]);
            offset += 2;

            if ext_data.len() < offset + 2 {
                return Err(Error::Decode(
                    "malformed extension: insufficient data for length".into(),
                ));
            }
            let ext_len = u16::from_be_bytes([ext_data[offset], ext_data[offset + 1]]) as usize;
            offset += 2;

            if ext_data.len() < offset + ext_len {
                return Err(Error::Decode(
                    "malformed extension: insufficient data for content".into(),
                ));
            }

            if ext_type == ECH_AUTH_EXTENSION_TYPE {
                let auth = ECHAuth::decode(&ext_data[offset..offset + ext_len])?;
                return Ok(Some(auth));
            }

            offset += ext_len;
        }

        Ok(None)
    }
}

/// Validate that ech_auth extension, if present, is the last extension
/// COMPLIANCE: Section 5.1 MUST requirement
fn validate_extension_ordering(extensions: &[u8]) -> Result<()> {
    if extensions.is_empty() {
        return Ok(());
    }

    let mut offset = 0;
    let mut found_ech_auth = false;

    while offset < extensions.len() {
        if extensions.len() < offset + 2 {
            return Err(Error::Decode(
                "malformed extension: insufficient data for type".into(),
            ));
        }
        let ext_type = u16::from_be_bytes([extensions[offset], extensions[offset + 1]]);
        offset += 2;

        if extensions.len() < offset + 2 {
            return Err(Error::Decode(
                "malformed extension: insufficient data for length".into(),
            ));
        }
        let ext_len = u16::from_be_bytes([extensions[offset], extensions[offset + 1]]) as usize;
        offset += 2;

        if extensions.len() < offset + ext_len {
            return Err(Error::Decode(
                "malformed extension: insufficient data for content".into(),
            ));
        }

        // Check if ech_auth was already seen (it should be last)
        if found_ech_auth {
            return Err(Error::Decode(
                "ech_auth extension MUST be last (found extension after ech_auth)".into(),
            ));
        }

        if ext_type == ECH_AUTH_EXTENSION_TYPE {
            found_ech_auth = true;
        }

        offset += ext_len;
    }

    Ok(())
}

/// Builder for ECHConfig
pub struct ECHConfigBuilder {
    config_id: u8,
    kem_id: u16,
    public_key: Vec<u8>,
    cipher_suites: Vec<HpkeSymmetricCipherSuite>,
    maximum_name_length: u8,
    public_name: String,
}

impl ECHConfigBuilder {
    pub fn new() -> Self {
        Self {
            config_id: 0,
            kem_id: DHKEM_X25519_SHA256,
            public_key: Vec::new(),
            cipher_suites: Vec::new(),
            maximum_name_length: 0,
            public_name: String::new(),
        }
    }

    pub fn config_id(mut self, id: u8) -> Self {
        self.config_id = id;
        self
    }

    pub fn kem_id(mut self, kem: u16) -> Self {
        self.kem_id = kem;
        self
    }

    pub fn public_key(mut self, key: Vec<u8>) -> Self {
        self.public_key = key;
        self
    }

    pub fn add_cipher_suite(mut self, kdf: u16, aead: u16) -> Self {
        self.cipher_suites.push(HpkeSymmetricCipherSuite {
            kdf_id: kdf,
            aead_id: aead,
        });
        self
    }

    pub fn maximum_name_length(mut self, len: u8) -> Self {
        self.maximum_name_length = len;
        self
    }

    pub fn public_name(mut self, name: &str) -> Self {
        self.public_name = name.to_string();
        self
    }

    pub fn build(self) -> Result<ECHConfig> {
        if self.public_key.is_empty() {
            return Err(Error::Decode("public_key is required".into()));
        }
        if self.cipher_suites.is_empty() {
            return Err(Error::Decode(
                "at least one cipher_suite is required".into(),
            ));
        }
        if self.public_name.is_empty() {
            return Err(Error::Decode("public_name is required".into()));
        }
        if self.public_name.len() > 255 {
            return Err(Error::Decode("public_name exceeds 255 bytes".into()));
        }

        Ok(ECHConfig {
            version: ECH_VERSION,
            config_id: self.config_id,
            kem_id: self.kem_id,
            public_key: self.public_key,
            cipher_suites: self.cipher_suites,
            maximum_name_length: self.maximum_name_length,
            public_name: self.public_name,
            extensions: Vec::new(),
        })
    }
}

impl Default for ECHConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ech_config_encode_decode() {
        let config = ECHConfig {
            version: ECH_VERSION,
            config_id: 42,
            kem_id: DHKEM_X25519_SHA256,
            public_key: vec![1u8; 32],
            cipher_suites: vec![
                HpkeSymmetricCipherSuite {
                    kdf_id: HKDF_SHA256,
                    aead_id: AES_128_GCM,
                },
                HpkeSymmetricCipherSuite {
                    kdf_id: HKDF_SHA256,
                    aead_id: CHACHA20_POLY1305,
                },
            ],
            maximum_name_length: 64,
            public_name: "example.com".to_string(),
            extensions: vec![],
        };

        let encoded = config.encode();
        let decoded = ECHConfig::decode(&encoded).unwrap();

        assert_eq!(config, decoded);
    }

    #[test]
    fn test_ech_config_builder() {
        let config = ECHConfigBuilder::new()
            .config_id(1)
            .kem_id(DHKEM_X25519_SHA256)
            .public_key(vec![0u8; 32])
            .add_cipher_suite(HKDF_SHA256, AES_128_GCM)
            .add_cipher_suite(HKDF_SHA256, AES_256_GCM)
            .maximum_name_length(64)
            .public_name("test.example")
            .build()
            .unwrap();

        assert_eq!(config.config_id, 1);
        assert_eq!(config.public_name, "test.example");
        assert_eq!(config.cipher_suites.len(), 2);
    }

    #[test]
    fn test_ech_config_builder_missing_fields() {
        let result = ECHConfigBuilder::new().public_name("test.example").build();
        assert!(result.is_err());

        let result = ECHConfigBuilder::new().public_key(vec![0u8; 32]).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_ech_config_with_extensions() {
        // Create valid extension: type=0x0001, length=0x0002, data=[0xAA, 0xBB]
        let valid_extension = vec![
            0x00, 0x01, // extension type
            0x00, 0x02, // extension length
            0xAA, 0xBB, // extension data
        ];

        let config = ECHConfig {
            version: ECH_VERSION,
            config_id: 1,
            kem_id: DHKEM_X25519_SHA256,
            public_key: vec![2u8; 32],
            cipher_suites: vec![HpkeSymmetricCipherSuite {
                kdf_id: HKDF_SHA256,
                aead_id: AES_128_GCM,
            }],
            maximum_name_length: 64,
            public_name: "test.com".to_string(),
            extensions: valid_extension.clone(),
        };

        let encoded = config.encode();
        let decoded = ECHConfig::decode(&encoded).unwrap();

        assert_eq!(config, decoded);
        assert_eq!(decoded.extensions, valid_extension);
    }

    #[test]
    fn test_extension_ordering_ech_auth_must_be_last() {
        // Create config with ech_auth extension followed by another extension (invalid)
        let invalid_extensions = vec![
            0xfe, 0x0d, // ech_auth extension type
            0x00, 0x01, // length
            0x00, // data (method=RPK)
            0x00, 0x01, // another extension type
            0x00, 0x02, // length
            0xAA, 0xBB, // data
        ];

        let config = ECHConfig {
            version: ECH_VERSION,
            config_id: 1,
            kem_id: DHKEM_X25519_SHA256,
            public_key: vec![2u8; 32],
            cipher_suites: vec![HpkeSymmetricCipherSuite {
                kdf_id: HKDF_SHA256,
                aead_id: AES_128_GCM,
            }],
            maximum_name_length: 64,
            public_name: "test.com".to_string(),
            extensions: invalid_extensions,
        };

        let encoded = config.encode();
        let result = ECHConfig::decode(&encoded);

        // Should fail because ech_auth is not last
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("ech_auth extension MUST be last"));
    }

    #[test]
    fn test_extension_ordering_ech_auth_last_is_valid() {
        // Create config with another extension followed by ech_auth (valid)
        let valid_extensions = vec![
            0x00, 0x01, // another extension type
            0x00, 0x02, // length
            0xAA, 0xBB, // data
            0xfe, 0x0d, // ech_auth extension type (last)
            0x00, 0x01, // length
            0x00, // data (method=RPK)
        ];

        let config = ECHConfig {
            version: ECH_VERSION,
            config_id: 1,
            kem_id: DHKEM_X25519_SHA256,
            public_key: vec![2u8; 32],
            cipher_suites: vec![HpkeSymmetricCipherSuite {
                kdf_id: HKDF_SHA256,
                aead_id: AES_128_GCM,
            }],
            maximum_name_length: 64,
            public_name: "test.com".to_string(),
            extensions: valid_extensions.clone(),
        };

        let encoded = config.encode();
        let decoded = ECHConfig::decode(&encoded).unwrap();

        // Should succeed because ech_auth is last
        assert_eq!(decoded.extensions, valid_extensions);
    }

    #[test]
    fn test_extract_ech_auth_present() {
        let config = ECHConfigBuilder::new()
            .config_id(1)
            .kem_id(DHKEM_X25519_SHA256)
            .public_key(vec![0u8; 32])
            .add_cipher_suite(HKDF_SHA256, AES_128_GCM)
            .public_name("example.com")
            .build()
            .unwrap();

        // Add ech_auth extension manually
        let auth = crate::ECHAuth {
            method: crate::ECHAuthMethod::Rpk,
            trusted_keys: vec![],
            signature: None,
        };
        let signed = config.with_ech_auth(&auth);
        let decoded = ECHConfig::decode(&signed).unwrap();

        // Extract should find the auth
        let extracted = decoded.extract_ech_auth().unwrap();
        assert!(extracted.is_some());
        assert_eq!(extracted.unwrap().method, crate::ECHAuthMethod::Rpk);
    }

    #[test]
    fn test_extract_ech_auth_absent() {
        let config = ECHConfigBuilder::new()
            .config_id(1)
            .kem_id(DHKEM_X25519_SHA256)
            .public_key(vec![0u8; 32])
            .add_cipher_suite(HKDF_SHA256, AES_128_GCM)
            .public_name("example.com")
            .build()
            .unwrap();

        // Config without ech_auth
        let extracted = config.extract_ech_auth().unwrap();
        assert!(extracted.is_none());
    }
}
