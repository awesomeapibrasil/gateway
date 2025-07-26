use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::time::Duration;

use crate::error::{GatewayError, Result};

/// Main gateway configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub waf: WafConfig,
    pub cache: CacheConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub monitoring: MonitoringConfig,
    pub plugins: PluginConfig,
    pub upstream: UpstreamConfig,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind_address: String,
    pub worker_threads: usize,
    pub debug: bool,
    pub max_connections: usize,
    pub connection_timeout: Duration,
    pub keep_alive_timeout: Duration,
    pub graceful_shutdown_timeout: Duration,
    pub tls: Option<TlsConfig>,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: Option<String>,
    pub require_client_cert: bool,
}

/// WAF configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst_limit: u32,
    pub window_size: Duration,
    pub storage_backend: String, // "memory", "redis", "database"
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub enabled: bool,
    pub backend: String, // "memory", "redis", "distributed"
    pub ttl: Duration,
    pub max_size: usize,
    pub compression: bool,
    pub redis: Option<RedisConfig>,
}

/// Redis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: u32,
    pub timeout: Duration,
    pub cluster: bool,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub enabled: bool,
    pub backend: String, // "postgres", "mysql", "mongodb", "dynamodb", "firebase"
    pub url: String,
    pub pool_size: u32,
    pub timeout: Duration,
    pub migrations_path: String,
    pub ssl_mode: String,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthConfig {
    pub enabled: bool,
    pub jwt_secret: String,
    pub jwt_expiry: Duration,
    pub providers: HashMap<String, AuthProviderConfig>,
    pub require_auth: bool,
    pub public_paths: Vec<String>,
}

/// Authentication provider configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthProviderConfig {
    pub provider_type: String, // "jwt", "oauth2", "ldap", "saml"
    pub config: HashMap<String, String>,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MonitoringConfig {
    pub enabled: bool,
    pub metrics_port: u16,
    pub log_level: String,
    pub prometheus: PrometheusConfig,
    pub tracing: TracingConfig,
    pub health_check_path: String,
}

/// Prometheus configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PrometheusConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub namespace: String,
}

/// Tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TracingConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub sample_rate: f64,
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PluginConfig {
    pub enabled: bool,
    pub plugin_dir: String,
    pub plugins: HashMap<String, PluginInstanceConfig>,
}

/// Plugin instance configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PluginInstanceConfig {
    pub enabled: bool,
    pub config: HashMap<String, serde_json::Value>,
}

/// Upstream configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpstreamConfig {
    pub backends: Vec<BackendConfig>,
    pub load_balancing: LoadBalancingConfig,
    pub health_check: HealthCheckConfig,
    pub circuit_breaker: CircuitBreakerConfig,
}

/// Backend configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackendConfig {
    pub name: String,
    pub address: String,
    pub weight: u32,
    pub health_check_path: String,
    pub max_connections: usize,
    pub timeout: Duration,
}

/// Load balancing configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoadBalancingConfig {
    pub algorithm: String, // "round_robin", "least_connections", "ip_hash", "weighted"
    pub sticky_sessions: bool,
    pub session_cookie: String,
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub interval: Duration,
    pub timeout: Duration,
    pub retries: u32,
    pub path: String,
    pub expected_status: u16,
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CircuitBreakerConfig {
    pub enabled: bool,
    pub failure_threshold: u32,
    pub timeout: Duration,
    pub half_open_max_calls: u32,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            waf: WafConfig::default(),
            cache: CacheConfig::default(),
            database: DatabaseConfig::default(),
            auth: AuthConfig::default(),
            monitoring: MonitoringConfig::default(),
            plugins: PluginConfig::default(),
            upstream: UpstreamConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:8080".to_string(),
            worker_threads: 4,
            debug: false,
            max_connections: 10000,
            connection_timeout: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(60),
            graceful_shutdown_timeout: Duration::from_secs(30),
            tls: None,
        }
    }
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
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: 1000,
            burst_limit: 100,
            window_size: Duration::from_secs(60),
            storage_backend: "memory".to_string(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: "memory".to_string(),
            ttl: Duration::from_secs(300), // 5 minutes
            max_size: 100 * 1024 * 1024,   // 100MB
            compression: true,
            redis: None,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: "postgres".to_string(),
            url: "postgresql://localhost:5432/gateway".to_string(),
            pool_size: 10,
            timeout: Duration::from_secs(30),
            migrations_path: "migrations".to_string(),
            ssl_mode: "prefer".to_string(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            jwt_secret: "change-me-in-production".to_string(),
            jwt_expiry: Duration::from_secs(3600), // 1 hour
            providers: HashMap::new(),
            require_auth: false,
            public_paths: vec!["/health".to_string(), "/metrics".to_string()],
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            metrics_port: 9090,
            log_level: "info".to_string(),
            prometheus: PrometheusConfig::default(),
            tracing: TracingConfig::default(),
            health_check_path: "/health".to_string(),
        }
    }
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: "/metrics".to_string(),
            namespace: "gateway".to_string(),
        }
    }
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://localhost:14268/api/traces".to_string(),
            sample_rate: 0.1,
        }
    }
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            plugin_dir: "plugins".to_string(),
            plugins: HashMap::new(),
        }
    }
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            backends: vec![BackendConfig::default()],
            load_balancing: LoadBalancingConfig::default(),
            health_check: HealthCheckConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
        }
    }
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            address: "http://localhost:3000".to_string(),
            weight: 1,
            health_check_path: "/health".to_string(),
            max_connections: 100,
            timeout: Duration::from_secs(30),
        }
    }
}

impl Default for LoadBalancingConfig {
    fn default() -> Self {
        Self {
            algorithm: "round_robin".to_string(),
            sticky_sessions: false,
            session_cookie: "JSESSIONID".to_string(),
        }
    }
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            retries: 3,
            path: "/health".to_string(),
            expected_status: 200,
        }
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: 5,
            timeout: Duration::from_secs(60),
            half_open_max_calls: 3,
        }
    }
}

impl GatewayConfig {
    /// Load configuration from a file
    pub fn from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            GatewayError::ConfigError(format!("Failed to read config file {}: {}", path, e))
        })?;

        let config: GatewayConfig = if path.ends_with(".yaml") || path.ends_with(".yml") {
            serde_yaml::from_str(&content).map_err(|e| {
                GatewayError::ConfigError(format!("Failed to parse YAML config: {}", e))
            })?
        } else if path.ends_with(".toml") {
            toml::from_str(&content).map_err(|e| {
                GatewayError::ConfigError(format!("Failed to parse TOML config: {}", e))
            })?
        } else {
            return Err(GatewayError::ConfigError(
                "Unsupported config file format. Use .yaml, .yml, or .toml".to_string(),
            ));
        };

        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate bind address
        if self.server.bind_address.parse::<SocketAddr>().is_err() {
            return Err(GatewayError::ConfigError(
                "Invalid bind address".to_string(),
            ));
        }

        // Validate worker threads
        if self.server.worker_threads == 0 {
            return Err(GatewayError::ConfigError(
                "Worker threads must be greater than 0".to_string(),
            ));
        }

        // Validate upstream backends
        if self.upstream.backends.is_empty() {
            return Err(GatewayError::ConfigError(
                "At least one backend must be configured".to_string(),
            ));
        }

        for backend in &self.upstream.backends {
            if backend.address.is_empty() {
                return Err(GatewayError::ConfigError(
                    "Backend address cannot be empty".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Save configuration to a file
    pub fn to_file(&self, path: &str) -> Result<()> {
        let content = if path.ends_with(".yaml") || path.ends_with(".yml") {
            serde_yaml::to_string(self).map_err(|e| {
                GatewayError::ConfigError(format!("Failed to serialize to YAML: {}", e))
            })?
        } else if path.ends_with(".toml") {
            toml::to_string(self).map_err(|e| {
                GatewayError::ConfigError(format!("Failed to serialize to TOML: {}", e))
            })?
        } else {
            return Err(GatewayError::ConfigError(
                "Unsupported config file format. Use .yaml, .yml, or .toml".to_string(),
            ));
        };

        fs::write(path, content).map_err(|e| {
            GatewayError::ConfigError(format!("Failed to write config file {}: {}", path, e))
        })?;

        Ok(())
    }
}
