//! Pingora Configuration Adapter
//!
//! This module adapts the gateway's configuration system to work with Pingora's
//! configuration model, providing seamless integration between both systems.

use pingora::server::configuration::ServerConf;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::config::GatewayConfig;
use crate::error::{GatewayError, Result};

/// Pingora configuration adapter that bridges gateway config to Pingora
pub struct PingoraConfigAdapter {
    gateway_config: GatewayConfig,
    pingora_config: ServerConf,
}

impl PingoraConfigAdapter {
    /// Create a new configuration adapter
    pub fn new(gateway_config: GatewayConfig) -> Result<Self> {
        info!("Creating Pingora configuration adapter");

        let pingora_config = Self::build_pingora_config(&gateway_config)?;

        Ok(Self {
            gateway_config,
            pingora_config,
        })
    }

    /// Build Pingora server configuration from gateway config
    fn build_pingora_config(config: &GatewayConfig) -> Result<ServerConf> {
        debug!("Building Pingora server configuration");

        // Create a comprehensive ServerConf based on gateway config
        let mut pingora_conf = ServerConf::new().ok_or_else(|| {
            GatewayError::ConfigError("Failed to create Pingora server configuration".to_string())
        })?;

        // Configure threading based on server settings
        pingora_conf.threads = config.server.worker_threads;

        // Configure graceful shutdown based on gateway config
        pingora_conf.grace_period_seconds = Some(config.server.graceful_shutdown_timeout.as_secs());
        pingora_conf.graceful_shutdown_timeout_seconds = Some(10);

        // Configure error log
        pingora_conf.error_log = Some("/var/log/gateway/error.log".to_string());

        // Configure PID file
        pingora_conf.pid_file = "/var/run/gateway.pid".to_string();

        // Configure upgrade socket for zero-downtime deployment
        pingora_conf.upgrade_sock = "/tmp/gateway_upgrade.sock".to_string();

        debug!("Pingora server configuration built successfully");
        Ok(pingora_conf)
    }

    /// Get the Pingora server configuration
    pub fn get_pingora_config(&self) -> &ServerConf {
        &self.pingora_config
    }

    /// Get the gateway configuration
    pub fn get_gateway_config(&self) -> &GatewayConfig {
        &self.gateway_config
    }

    /// Update configuration at runtime
    pub fn update_config(&mut self, new_config: GatewayConfig) -> Result<()> {
        info!("Updating Pingora configuration adapter");

        // Validate new configuration
        new_config.validate()?;

        // Rebuild Pingora configuration
        let new_pingora_config = Self::build_pingora_config(&new_config)?;

        self.gateway_config = new_config;
        self.pingora_config = new_pingora_config;

        info!("Configuration updated successfully");
        Ok(())
    }

    /// Generate Pingora service configuration
    pub fn generate_service_config(&self) -> PingoraServiceConfig {
        debug!("Generating Pingora service configuration");

        PingoraServiceConfig {
            // HTTP listeners
            http_listeners: self.generate_http_listeners(),

            // HTTPS listeners
            https_listeners: self.generate_https_listeners(),

            // Load balancer configuration
            load_balancer: self.generate_load_balancer_config(),

            // Cache configuration
            cache: self.generate_cache_config(),

            // Health check configuration
            health_check: self.generate_health_check_config(),

            // Circuit breaker configuration
            circuit_breaker: self.generate_circuit_breaker_config(),

            // Metrics configuration
            metrics: self.generate_metrics_config(),
        }
    }

    /// Generate HTTP listener configurations
    fn generate_http_listeners(&self) -> Vec<HttpListenerConfig> {
        let mut listeners = Vec::new();

        // Parse bind address
        if let Ok(addr) = self
            .gateway_config
            .server
            .bind_address
            .parse::<std::net::SocketAddr>()
        {
            listeners.push(HttpListenerConfig {
                address: addr,
                proxy_protocol: false,
                ipv6_only: false,
            });
        } else {
            warn!(
                "Invalid bind address: {}",
                self.gateway_config.server.bind_address
            );
            // Default fallback
            listeners.push(HttpListenerConfig {
                address: "0.0.0.0:8080".parse().unwrap(),
                proxy_protocol: false,
                ipv6_only: false,
            });
        }

        listeners
    }

    /// Generate HTTPS listener configurations
    fn generate_https_listeners(&self) -> Vec<HttpsListenerConfig> {
        let mut listeners = Vec::new();

        if self.gateway_config.ssl.enabled {
            // Parse bind address and create HTTPS version
            if let Ok(addr) = self
                .gateway_config
                .server
                .bind_address
                .parse::<std::net::SocketAddr>()
            {
                let https_port = if addr.port() == 80 {
                    443
                } else {
                    addr.port() + 1
                };
                let https_addr = std::net::SocketAddr::new(addr.ip(), https_port);

                listeners.push(HttpsListenerConfig {
                    address: https_addr,
                    cert_path: self
                        .gateway_config
                        .server
                        .tls
                        .as_ref()
                        .map(|tls| tls.cert_path.clone())
                        .unwrap_or_else(|| "/etc/ssl/certs/gateway.crt".to_string()),
                    key_path: self
                        .gateway_config
                        .server
                        .tls
                        .as_ref()
                        .map(|tls| tls.key_path.clone())
                        .unwrap_or_else(|| "/etc/ssl/private/gateway.key".to_string()),
                    require_client_cert: self
                        .gateway_config
                        .server
                        .tls
                        .as_ref()
                        .map(|tls| tls.require_client_cert)
                        .unwrap_or(false),
                    ca_path: self
                        .gateway_config
                        .server
                        .tls
                        .as_ref()
                        .and_then(|tls| tls.ca_path.clone()),
                });
            }
        }

        listeners
    }

    /// Generate load balancer configuration
    fn generate_load_balancer_config(&self) -> LoadBalancingConfig {
        self.gateway_config.upstream.load_balancing.clone()
    }

    /// Generate cache configuration
    fn generate_cache_config(&self) -> CacheConfig {
        CacheConfig {
            enabled: self.gateway_config.cache.enabled,
            backend: self.gateway_config.cache.backend.clone(),
            ttl: self.gateway_config.cache.ttl,
            max_size: self.gateway_config.cache.max_size,
            compression: self.gateway_config.cache.compression,
            redis: self.gateway_config.cache.redis.clone(),
        }
    }

    /// Generate health check configuration
    fn generate_health_check_config(&self) -> HealthCheckConfig {
        HealthCheckConfig {
            enabled: self.gateway_config.upstream.health_check.enabled,
            interval: self.gateway_config.upstream.health_check.interval,
            timeout: self.gateway_config.upstream.health_check.timeout,
            retries: self.gateway_config.upstream.health_check.retries,
            path: self.gateway_config.upstream.health_check.path.clone(),
            expected_status: self.gateway_config.upstream.health_check.expected_status,
        }
    }

    /// Generate circuit breaker configuration
    fn generate_circuit_breaker_config(&self) -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            enabled: self.gateway_config.upstream.circuit_breaker.enabled,
            failure_threshold: self
                .gateway_config
                .upstream
                .circuit_breaker
                .failure_threshold,
            timeout: self.gateway_config.upstream.circuit_breaker.timeout,
            half_open_max_calls: self
                .gateway_config
                .upstream
                .circuit_breaker
                .half_open_max_calls,
        }
    }

    /// Generate metrics configuration
    fn generate_metrics_config(&self) -> MetricsConfig {
        MetricsConfig {
            enabled: self.gateway_config.monitoring.enabled,
            prometheus: PrometheusConfig {
                enabled: self.gateway_config.monitoring.prometheus.enabled,
                endpoint: self.gateway_config.monitoring.prometheus.endpoint.clone(),
                namespace: self.gateway_config.monitoring.prometheus.namespace.clone(),
            },
            port: self.gateway_config.monitoring.metrics_port,
        }
    }

    /// Validate configuration compatibility
    pub fn validate_pingora_compatibility(&self) -> Result<Vec<String>> {
        let mut warnings = Vec::new();

        // Check for unsupported features
        if self.gateway_config.plugins.enabled && !self.gateway_config.plugins.plugins.is_empty() {
            warnings.push(
                "Some plugin features may need adaptation for Pingora integration".to_string(),
            );
        }

        if self.gateway_config.ingress.enabled {
            warnings.push(
                "Ingress controller functionality may need specific Pingora integration"
                    .to_string(),
            );
        }

        // Check resource limits
        if self.gateway_config.server.max_connections > 100000 {
            warnings.push(
                "Very high connection limits may require system tuning for Pingora".to_string(),
            );
        }

        // Check timeout configurations
        if self.gateway_config.server.connection_timeout < Duration::from_secs(1) {
            warnings
                .push("Very short connection timeouts may cause issues with Pingora".to_string());
        }

        if warnings.is_empty() {
            info!("Pingora compatibility validation passed");
        } else {
            warn!(
                "Pingora compatibility validation found {} warnings",
                warnings.len()
            );
        }

        Ok(warnings)
    }
}

/// Complete service configuration for Pingora
#[derive(Debug, Clone)]
pub struct PingoraServiceConfig {
    pub http_listeners: Vec<HttpListenerConfig>,
    pub https_listeners: Vec<HttpsListenerConfig>,
    pub load_balancer: LoadBalancingConfig,
    pub cache: CacheConfig,
    pub health_check: HealthCheckConfig,
    pub circuit_breaker: CircuitBreakerConfig,
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone)]
pub struct HttpListenerConfig {
    pub address: std::net::SocketAddr,
    pub proxy_protocol: bool,
    pub ipv6_only: bool,
}

#[derive(Debug, Clone)]
pub struct HttpsListenerConfig {
    pub address: std::net::SocketAddr,
    pub cert_path: String,
    pub key_path: String,
    pub require_client_cert: bool,
    pub ca_path: Option<String>,
}

// Re-export configuration types from the main config module
pub use crate::config::{
    BackendConfig, CircuitBreakerConfig, HealthCheckConfig, LoadBalancingConfig,
};

// Additional configuration types for Pingora-specific settings
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub enabled: bool,
    pub backend: String,
    pub ttl: Duration,
    pub max_size: usize,
    pub compression: bool,
    pub redis: Option<crate::config::RedisConfig>,
}

#[derive(Debug, Clone)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub prometheus: PrometheusConfig,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct PrometheusConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub namespace: String,
}
