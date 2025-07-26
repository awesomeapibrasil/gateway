use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// HTTP method enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    TRACE,
    CONNECT,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::GET => write!(f, "GET"),
            HttpMethod::POST => write!(f, "POST"),
            HttpMethod::PUT => write!(f, "PUT"),
            HttpMethod::DELETE => write!(f, "DELETE"),
            HttpMethod::PATCH => write!(f, "PATCH"),
            HttpMethod::HEAD => write!(f, "HEAD"),
            HttpMethod::OPTIONS => write!(f, "OPTIONS"),
            HttpMethod::TRACE => write!(f, "TRACE"),
            HttpMethod::CONNECT => write!(f, "CONNECT"),
        }
    }
}

impl From<&http::Method> for HttpMethod {
    fn from(method: &http::Method) -> Self {
        match method {
            &http::Method::GET => HttpMethod::GET,
            &http::Method::POST => HttpMethod::POST,
            &http::Method::PUT => HttpMethod::PUT,
            &http::Method::DELETE => HttpMethod::DELETE,
            &http::Method::PATCH => HttpMethod::PATCH,
            &http::Method::HEAD => HttpMethod::HEAD,
            &http::Method::OPTIONS => HttpMethod::OPTIONS,
            &http::Method::TRACE => HttpMethod::TRACE,
            &http::Method::CONNECT => HttpMethod::CONNECT,
            _ => HttpMethod::GET, // Default fallback
        }
    }
}

/// Request metadata extracted from incoming requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetadata {
    pub method: HttpMethod,
    pub uri: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub client_ip: IpAddr,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub timestamp: SystemTime,
    pub request_id: String,
}

/// Response metadata for tracking response characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetadata {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub content_length: Option<u64>,
    pub processing_time: Duration,
    pub backend_time: Option<Duration>,
    pub cache_hit: bool,
    pub error: Option<String>,
}

/// Backend server information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backend {
    pub name: String,
    pub address: String,
    pub weight: u32,
    pub healthy: bool,
    pub last_health_check: SystemTime,
    pub active_connections: u32,
    pub total_requests: u64,
    pub failed_requests: u64,
    pub average_response_time: Duration,
}

/// Circuit breaker states
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

/// Circuit breaker information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreaker {
    pub state: CircuitBreakerState,
    pub failure_count: u32,
    pub last_failure_time: Option<SystemTime>,
    pub next_attempt_time: Option<SystemTime>,
    pub success_count: u32,
}

/// Rate limiter entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitEntry {
    pub key: String,
    pub requests: u32,
    pub window_start: SystemTime,
    pub last_request: SystemTime,
}

/// Authentication context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub authenticated: bool,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub token_type: Option<String>,
    pub expires_at: Option<SystemTime>,
    pub metadata: HashMap<String, String>,
}

/// WAF rule result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleResult {
    Allow,
    Block,
    Log,
    Rate,
}

/// WAF rule action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafAction {
    pub result: RuleResult,
    pub rule_id: String,
    pub message: String,
    pub score: Option<u32>,
    pub metadata: HashMap<String, String>,
}

/// Cache entry metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub content_type: Option<String>,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub access_count: u64,
    pub last_accessed: SystemTime,
    pub size: usize,
    pub compressed: bool,
}

/// Health check status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub status: HealthStatus,
    pub last_check: SystemTime,
    pub response_time: Duration,
    pub status_code: Option<u16>,
    pub error: Option<String>,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
}

/// Plugin context for plugin execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginContext {
    pub request: RequestMetadata,
    pub response: Option<ResponseMetadata>,
    pub auth: Option<AuthContext>,
    pub backend: Option<Backend>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Load balancing algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LoadBalanceAlgorithm {
    RoundRobin,
    LeastConnections,
    WeightedRoundRobin,
    IpHash,
    Random,
    LeastResponseTime,
}

/// Gateway statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayStats {
    pub total_requests: u64,
    pub total_responses: u64,
    pub active_connections: u32,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub waf_blocks: u64,
    pub rate_limit_blocks: u64,
    pub backend_errors: u64,
    pub average_response_time: Duration,
    pub uptime: Duration,
    pub memory_usage: u64,
    pub cpu_usage: f64,
}

/// Configuration update notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigUpdate {
    pub section: String,
    pub old_value: serde_json::Value,
    pub new_value: serde_json::Value,
    pub timestamp: SystemTime,
    pub source: String,
}

/// Event types for the gateway event system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GatewayEvent {
    RequestReceived(RequestMetadata),
    RequestProcessed(RequestMetadata, ResponseMetadata),
    WafBlock(RequestMetadata, WafAction),
    RateLimit(RequestMetadata, RateLimitEntry),
    BackendDown(Backend),
    BackendUp(Backend),
    CircuitBreakerOpen(String),
    CircuitBreakerClosed(String),
    ConfigUpdated(ConfigUpdate),
    PluginLoaded(String),
    PluginUnloaded(String),
    CacheInvalidated(String),
    AuthenticationFailed(RequestMetadata),
    AuthenticationSuccess(RequestMetadata, AuthContext),
}
