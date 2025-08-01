use thiserror::Error;

/// Gateway error types
#[derive(Error, Debug)]
pub enum GatewayError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Proxy error: {0}")]
    ProxyError(String),

    #[error("WAF error: {0}")]
    WafError(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Authentication error: {0}")]
    AuthError(String),

    #[error("Monitoring error: {0}")]
    MonitoringError(String),

    #[error("Plugin error: {0}")]
    PluginError(String),

    #[error("SSL/TLS error: {0}")]
    SslError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    HttpError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Timeout error: {0}")]
    TimeoutError(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitError(String),

    #[error("Upstream error: {0}")]
    UpstreamError(String),

    #[error("Circuit breaker open: {0}")]
    CircuitBreakerError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Result type alias for gateway operations
pub type Result<T> = std::result::Result<T, GatewayError>;

impl From<serde_json::Error> for GatewayError {
    fn from(err: serde_json::Error) -> Self {
        GatewayError::SerializationError(format!("JSON error: {}", err))
    }
}

impl From<serde_yaml::Error> for GatewayError {
    fn from(err: serde_yaml::Error) -> Self {
        GatewayError::SerializationError(format!("YAML error: {}", err))
    }
}

impl From<toml::de::Error> for GatewayError {
    fn from(err: toml::de::Error) -> Self {
        GatewayError::SerializationError(format!("TOML error: {}", err))
    }
}

impl From<hyper::Error> for GatewayError {
    fn from(err: hyper::Error) -> Self {
        GatewayError::HttpError(format!("Hyper error: {}", err))
    }
}

impl From<http::Error> for GatewayError {
    fn from(err: http::Error) -> Self {
        GatewayError::HttpError(format!("HTTP error: {}", err))
    }
}

impl From<url::ParseError> for GatewayError {
    fn from(err: url::ParseError) -> Self {
        GatewayError::NetworkError(format!("URL parse error: {}", err))
    }
}
