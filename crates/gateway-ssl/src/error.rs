use thiserror::Error;

/// SSL-related errors
#[derive(Error, Debug)]
pub enum SslError {
    #[error("ACME error: {0}")]
    AcmeError(String),

    #[error("Certificate error: {0}")]
    CertificateError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Vault error: {0}")]
    VaultError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("Ring error: {0}")]
    RingError(#[from] ring::error::Unspecified),

    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),

    #[error("File watcher error: {0}")]
    WatcherError(#[from] notify::Error),
}

/// Result type for SSL operations
pub type Result<T> = std::result::Result<T, SslError>;
