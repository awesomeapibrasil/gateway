use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Ingress annotations parser and manager
#[derive(Debug, Clone)]
pub struct IngressAnnotations {
    annotations: HashMap<String, String>,
    config: crate::config::IngressAnnotationsConfig,
}

/// Backend protocol configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BackendProtocol {
    Http,
    Https,
    Grpc,
    GrpcSecure,
    WebSocket,
    WebSocketSecure,
}

/// Rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitAnnotation {
    pub requests_per_minute: u32,
    pub burst: Option<u32>,
    pub key: Option<String>, // "ip", "header:X-User-ID", "jwt:sub"
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAnnotation {
    pub auth_type: String, // "basic", "jwt", "oauth2", "ldap"
    pub realm: Option<String>,
    pub auth_url: Option<String>,
    pub auth_headers: Option<Vec<String>>,
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginAnnotation {
    pub name: String,
    pub enabled: bool,
    pub config: HashMap<String, serde_json::Value>,
}

/// Load balancer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerAnnotation {
    pub algorithm: String, // "round_robin", "least_connections", "ip_hash", "weighted"
    pub sticky_sessions: bool,
    pub health_check: bool,
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerAnnotation {
    pub enabled: bool,
    pub failure_threshold: u32,
    pub timeout_seconds: u32,
    pub half_open_max_calls: u32,
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsAnnotation {
    pub enabled: bool,
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub exposed_headers: Vec<String>,
    pub max_age: Option<u32>,
    pub allow_credentials: bool,
}

/// Compression configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionAnnotation {
    pub enabled: bool,
    pub algorithms: Vec<String>, // "gzip", "brotli", "deflate"
    pub min_size: u32,
    pub types: Vec<String>, // MIME types
}

impl IngressAnnotations {
    /// Create new ingress annotations parser
    pub fn new(
        annotations: HashMap<String, String>,
        config: crate::config::IngressAnnotationsConfig,
    ) -> Self {
        Self {
            annotations,
            config,
        }
    }

    /// Get backend protocol
    pub fn get_backend_protocol(&self) -> BackendProtocol {
        self.annotations
            .get(&self.config.backend_protocol)
            .and_then(|v| match v.to_lowercase().as_str() {
                "http" => Some(BackendProtocol::Http),
                "https" => Some(BackendProtocol::Https),
                "grpc" => Some(BackendProtocol::Grpc),
                "grpc-secure" | "grpcs" => Some(BackendProtocol::GrpcSecure),
                "websocket" | "ws" => Some(BackendProtocol::WebSocket),
                "websocket-secure" | "wss" => Some(BackendProtocol::WebSocketSecure),
                _ => None,
            })
            .unwrap_or(BackendProtocol::Http)
    }

    /// Check if SSL redirect is enabled
    pub fn is_ssl_redirect_enabled(&self) -> bool {
        self.annotations
            .get(&self.config.ssl_redirect)
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false)
    }

    /// Get rate limit configuration
    pub fn get_rate_limit(&self) -> Option<RateLimitAnnotation> {
        self.annotations
            .get(&self.config.rate_limit)
            .and_then(|v| serde_json::from_str(v).ok())
    }

    /// Get authentication configuration
    pub fn get_auth(&self) -> Option<AuthAnnotation> {
        self.annotations
            .get(&self.config.auth_type)
            .and_then(|v| serde_json::from_str(v).ok())
    }

    /// Get plugins configuration
    pub fn get_plugins(&self) -> Vec<PluginAnnotation> {
        self.annotations
            .get(&self.config.plugins)
            .and_then(|v| serde_json::from_str(v).ok())
            .unwrap_or_default()
    }

    /// Get upstream timeout
    pub fn get_upstream_timeout(&self) -> Option<Duration> {
        self.annotations
            .get(&self.config.upstream_timeout)
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
    }

    /// Get load balancer configuration
    pub fn get_load_balancer(&self) -> Option<LoadBalancerAnnotation> {
        self.annotations
            .get(&self.config.load_balancer)
            .and_then(|v| serde_json::from_str(v).ok())
    }

    /// Get circuit breaker configuration
    pub fn get_circuit_breaker(&self) -> Option<CircuitBreakerAnnotation> {
        self.annotations
            .get(&self.config.circuit_breaker)
            .and_then(|v| serde_json::from_str(v).ok())
    }

    /// Get CORS configuration
    pub fn get_cors(&self) -> Option<CorsAnnotation> {
        self.annotations
            .get(&self.config.cors)
            .and_then(|v| serde_json::from_str(v).ok())
    }

    /// Get compression configuration
    pub fn get_compression(&self) -> Option<CompressionAnnotation> {
        self.annotations
            .get(&self.config.compression)
            .and_then(|v| serde_json::from_str(v).ok())
    }

    /// Get custom annotation value
    pub fn get_custom(&self, key: &str) -> Option<&String> {
        self.annotations.get(key)
    }

    /// Check if annotation exists
    pub fn has_annotation(&self, key: &str) -> bool {
        self.annotations.contains_key(key)
    }

    /// Get all annotations
    pub fn get_all(&self) -> &HashMap<String, String> {
        &self.annotations
    }
}

impl Default for BackendProtocol {
    fn default() -> Self {
        BackendProtocol::Http
    }
}

impl std::fmt::Display for BackendProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendProtocol::Http => write!(f, "http"),
            BackendProtocol::Https => write!(f, "https"),
            BackendProtocol::Grpc => write!(f, "grpc"),
            BackendProtocol::GrpcSecure => write!(f, "grpc-secure"),
            BackendProtocol::WebSocket => write!(f, "websocket"),
            BackendProtocol::WebSocketSecure => write!(f, "websocket-secure"),
        }
    }
}
