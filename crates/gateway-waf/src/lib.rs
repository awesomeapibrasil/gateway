//! Web Application Firewall (WAF) Module
//!
//! This module provides comprehensive Layer 7 filtering capabilities including:
//! - IP-based blocking and whitelisting
//! - Header-based filtering

#![allow(clippy::uninlined_format_args)]
#![allow(clippy::manual_strip)]
#![allow(clippy::for_kv_map)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::new_without_default)]
#![allow(clippy::inherent_to_string)]
#![allow(clippy::overly_complex_bool_expr)]
//! - URL and query string validation
//! - Rate limiting with distributed storage
//! - Complex rule engine similar to OPA
//! - Simple rule configuration for common use cases

pub mod engine;
pub mod header_filter;
pub mod ip_filter;
pub mod modsecurity_engine;
pub mod patterns;
pub mod rate_limiter;
pub mod rules;
pub mod url_filter;

#[cfg(test)]
mod modsecurity_tests;

pub use engine::WafEngine;
pub use header_filter::HeaderFilter;
pub use ip_filter::IpFilter;
pub use modsecurity_engine::{ModSecurityConfig, ModSecurityEngine, ModSecurityStats};
pub use rate_limiter::{RateLimitKey, RateLimiter};
pub use rules::{RuleAction, RuleCondition, WafRule, WafRuleSet};
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
    /// ModSecurity configuration
    pub modsecurity: crate::modsecurity_engine::ModSecurityConfig,
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules_path: "config/waf-rules.yaml".to_string(),
            rate_limiting: RateLimitConfig::default(),
            ip_whitelist: Vec::new(),
            ip_blacklist: Vec::new(),
            blocked_headers: Vec::new(),
            blocked_user_agents: Vec::new(),
            max_request_size: 10 * 1024 * 1024, // 10MB
            block_malicious_ips: true,
            modsecurity: crate::modsecurity_engine::ModSecurityConfig::default(),
        }
    }
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

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: 1000,
            burst_limit: 100,
            window_size: std::time::Duration::from_secs(60),
            storage_backend: "memory".to_string(),
        }
    }
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
