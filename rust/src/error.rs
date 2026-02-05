//! Error types for ECH authentication operations
//!
//! This module defines the error types returned by ECH authentication
//! functions. All errors implement the standard [`std::error::Error`] trait.
//!
//! # Common Error Types
//!
//! - [`Error::SignatureInvalid`] - Signature verification failed
//! - [`Error::Expired`] - Config expired (not_after < current time)
//! - [`Error::UntrustedKey`] - SPKI hash not in trusted_keys
//! - [`Error::Decode`] - Malformed wire format data
//! - [`Error::CertificateInvalid`] - PKIX certificate validation failed
//!
//! # Result Type Alias
//!
//! [`Result<T>`] is a convenient alias for `std::result::Result<T, Error>`.

/// Error types for ECH authentication operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Decode error (malformed wire format data)
    #[error("decode error: {0}")]
    Decode(String),

    /// Signature verification failed
    #[error("signature verification failed")]
    SignatureInvalid,

    /// SPKI hash not in trusted_keys list
    #[error("SPKI hash not in trusted_keys")]
    UntrustedKey,

    /// Config expired (not_after < current time)
    #[error("config expired: not_after {not_after} < current {current}")]
    Expired { not_after: u64, current: u64 },

    /// Unsupported authentication method
    #[error("unsupported method: {0}")]
    UnsupportedMethod(u8),

    /// Unsupported signature algorithm
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(u16),

    /// Signature block missing from ECHAuth
    #[error("signature block missing")]
    SignatureMissing,

    /// Invalid SPKI format
    #[error("invalid SPKI format: {0}")]
    InvalidSpki(String),

    /// Certificate validation failed
    #[error("certificate validation failed: {0}")]
    CertificateInvalid(String),

    /// Certificate chain validation failed
    #[error("certificate chain validation failed: {0}")]
    ChainValidationFailed(String),

    /// Certificate missing required extension
    #[error("certificate missing required extension: {0}")]
    MissingExtension(String),

    /// Certificate SAN does not match public_name
    #[error("certificate SAN does not match public_name")]
    SanMismatch,
}

/// Result type alias for ECH authentication operations
pub type Result<T> = std::result::Result<T, Error>;
