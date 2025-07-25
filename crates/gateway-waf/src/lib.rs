//! Web Application Firewall (WAF) Module
//! 
//! This module provides comprehensive Layer 7 filtering capabilities including:
//! - IP-based blocking and whitelisting
//! - Header-based filtering
//! - URL and query string validation
//! - Rate limiting with distributed storage
//! - Complex rule engine similar to OPA
//! - Simple rule configuration for common use cases

pub mod engine;
pub mod rules;
pub mod rate_limiter;
pub mod ip_filter;
pub mod header_filter;
pub mod url_filter;
pub mod patterns;

pub use engine::WafEngine;
pub use rules::{WafRule, WafRuleSet, RuleCondition, RuleAction};
pub use rate_limiter::{RateLimiter, RateLimitKey};
pub use ip_filter::IpFilter;
pub use header_filter::HeaderFilter;
pub use url_filter::UrlFilter;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// WAF configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WafConfig {
    pub enabled: bool,
    pub rules_path: String,
    pub rate_limiting: RateLimitConfig,
    pub ip_whitelist: Vec<String>,
    pub ip_blacklist: Vec<String>,
    pub blocked_headers: Vec<String>,
    pub blocked_user_agents: Vec<String>,
    pub max_request_size: usize,
    pub block_malicious_ips: bool,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst_limit: u32,
    pub window_size: std::time::Duration,
    pub storage_backend: String,
}

/// WAF evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WafResult {
    Allow,
    Block(String),
    RateLimit(String),
    Log(String),
}

/// Request context for WAF evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub method: String,
    pub uri: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub client_ip: IpAddr,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub body: Option<Vec<u8>>,
}

/// WAF statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WafStats {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub rate_limited_requests: u64,
    pub ip_blocks: u64,
    pub header_blocks: u64,
    pub url_blocks: u64,
    pub rule_matches: HashMap<String, u64>,
}

/// Error types for WAF operations
#[derive(thiserror::Error, Debug)]
pub enum WafError {
    #[error("Rule parsing error: {0}")]
    RuleParseError(String),

    #[error("Rate limiter error: {0}")]
    RateLimiterError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Pattern matching error: {0}")]
    PatternError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, WafError>;