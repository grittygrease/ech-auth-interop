/// Error types for ECH authentication operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("decode error: {0}")]
    Decode(String),

    #[error("signature verification failed")]
    SignatureInvalid,

    #[error("SPKI hash not in trusted_keys")]
    UntrustedKey,

    #[error("config expired: not_after {not_after} < current {current}")]
    Expired { not_after: u64, current: u64 },

    #[error("unsupported method: {0}")]
    UnsupportedMethod(u8),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(u16),

    #[error("signature block missing")]
    SignatureMissing,

    #[error("invalid SPKI format: {0}")]
    InvalidSpki(String),

    #[error("certificate validation failed: {0}")]
    CertificateInvalid(String),

    #[error("certificate chain validation failed: {0}")]
    ChainValidationFailed(String),

    #[error("certificate missing required extension: {0}")]
    MissingExtension(String),

    #[error("certificate SAN does not match public_name")]
    SanMismatch,
}

pub type Result<T> = std::result::Result<T, Error>;
