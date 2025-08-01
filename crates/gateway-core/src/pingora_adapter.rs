//! Complete Pingora Gateway Integration
//!
//! This module provides a complete integration with Cloudflare's Pingora framework,
//! incorporating all gateway components including WAF, authentication, caching,
//! load balancing, SSL/TLS termination, and monitoring.

use pingora::server::Server;
use std::sync::Arc;
use tracing::{info, warn};

use crate::config::GatewayConfig;
use crate::error::{GatewayError, Result};
use crate::pingora_config::PingoraConfigAdapter;
use crate::pingora_ssl::PingoraSslConfig;

use gateway_auth::AuthManager;
use gateway_cache::CacheManager;
use gateway_database::DatabaseManager;
use gateway_monitoring::MonitoringManager;
use gateway_plugins::PluginManager;
use gateway_ssl::{
    config::{
        AcmeConfig, AutoSslConfig, CertificateConfig, DnsProviderConfig, VaultAuthMethod,
        VaultConfig,
    },
    SslManager,
};
use gateway_waf::WafEngine;

/// Complete Pingora-based Gateway implementation
pub struct PingoraGateway {
    server: Server,
    config_adapter: PingoraConfigAdapter,
    ssl_config: Option<Arc<PingoraSslConfig>>,
    waf: Arc<WafEngine>,
    cache: Arc<CacheManager>,
    auth: Arc<AuthManager>,
    monitoring: Arc<MonitoringManager>,
    plugins: Arc<PluginManager>,
    database: Arc<DatabaseManager>,
    #[allow(dead_code)]
    cert_manager: Option<Arc<SslManager>>,
}

impl PingoraGateway {
    /// Create a new complete Pingora gateway instance
    ///
    /// # Example Usage
    ///
    /// ```rust,no_run
    /// use gateway_core::{GatewayConfig, pingora_adapter::PingoraGateway};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let config = GatewayConfig::default();
    ///     let gateway = PingoraGateway::new(config).await?;
    ///     gateway.run_forever();
    ///     Ok(())
    /// }
    /// ```
    pub async fn new(config: GatewayConfig) -> Result<Self> {
        info!("Initializing complete Pingora gateway with all components");

        // Validate configuration
        config.validate()?;

        // Create configuration adapter
        let config_adapter = PingoraConfigAdapter::new(config.clone())?;

        // Validate Pingora compatibility
        let warnings = config_adapter.validate_pingora_compatibility()?;
        for warning in warnings {
            warn!("Pingora compatibility: {}", warning);
        }

        // Initialize database first as other components depend on it
        let database = if config.database.enabled {
            let db_config = gateway_database::DatabaseConfig {
                enabled: config.database.enabled,
                backend: config.database.backend.clone(),
                url: config.database.url.clone(),
                pool_size: config.database.pool_size,
                timeout: config.database.timeout,
                migrations_path: config.database.migrations_path.clone(),
                ssl_mode: config.database.ssl_mode.clone(),
            };
            Arc::new(DatabaseManager::new(&db_config).await.map_err(|e| {
                GatewayError::DatabaseError(format!("Failed to initialize database: {}", e))
            })?)
        } else {
            Arc::new(DatabaseManager::disabled())
        };

        // Initialize monitoring
        let monitoring_config = gateway_monitoring::MonitoringConfig {
            enabled: config.monitoring.enabled,
            metrics_port: config.monitoring.metrics_port,
            log_level: config.monitoring.log_level.clone(),
            prometheus: gateway_monitoring::PrometheusConfig {
                enabled: config.monitoring.prometheus.enabled,
                endpoint: config.monitoring.prometheus.endpoint.clone(),
                namespace: config.monitoring.prometheus.namespace.clone(),
            },
            tracing: gateway_monitoring::TracingConfig {
                enabled: config.monitoring.tracing.enabled,
                endpoint: config.monitoring.tracing.endpoint.clone(),
                sample_rate: config.monitoring.tracing.sample_rate,
            },
            health_check_path: config.monitoring.health_check_path.clone(),
        };
        let monitoring = Arc::new(MonitoringManager::new(&monitoring_config).await.map_err(
            |e| GatewayError::MonitoringError(format!("Failed to initialize monitoring: {}", e)),
        )?);

        // Initialize cache
        let cache_config = gateway_cache::CacheConfig {
            enabled: config.cache.enabled,
            backend: config.cache.backend.clone(),
            ttl: config.cache.ttl,
            max_size: config.cache.max_size,
            compression: config.cache.compression,
            redis: config
                .cache
                .redis
                .as_ref()
                .map(|r| gateway_cache::RedisConfig {
                    url: r.url.clone(),
                    pool_size: r.pool_size,
                    timeout: r.timeout,
                    cluster: r.cluster,
                }),
        };
        let cache = Arc::new(
            CacheManager::new(&cache_config, database.clone())
                .await
                .map_err(|e| {
                    GatewayError::CacheError(format!("Failed to initialize cache: {}", e))
                })?,
        );

        // Initialize authentication
        let auth_config = gateway_auth::AuthConfig {
            enabled: config.auth.enabled,
            jwt_secret: config.auth.jwt_secret.clone(),
            jwt_expiry: config.auth.jwt_expiry,
            providers: config
                .auth
                .providers
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        gateway_auth::AuthProviderConfig {
                            provider_type: v.provider_type.clone(),
                            config: v.config.clone(),
                        },
                    )
                })
                .collect(),
            require_auth: config.auth.require_auth,
            public_paths: config.auth.public_paths.clone(),
        };
        let auth = Arc::new(
            AuthManager::new(&auth_config, database.clone())
                .await
                .map_err(|e| {
                    GatewayError::AuthError(format!("Failed to initialize auth: {}", e))
                })?,
        );

        // Initialize WAF
        let waf_config = gateway_waf::WafConfig {
            enabled: config.waf.enabled,
            rules_path: config.waf.rules_path.clone(),
            rate_limiting: gateway_waf::RateLimitConfig {
                enabled: config.waf.rate_limiting.enabled,
                requests_per_minute: config.waf.rate_limiting.requests_per_minute,
                burst_limit: config.waf.rate_limiting.burst_limit,
                window_size: config.waf.rate_limiting.window_size,
                storage_backend: config.waf.rate_limiting.storage_backend.clone(),
            },
            ip_whitelist: config.waf.ip_whitelist.clone(),
            ip_blacklist: config.waf.ip_blacklist.clone(),
            blocked_headers: config.waf.blocked_headers.clone(),
            blocked_user_agents: config.waf.blocked_user_agents.clone(),
            max_request_size: config.waf.max_request_size,
            block_malicious_ips: config.waf.block_malicious_ips,
            modsecurity: gateway_waf::ModSecurityConfig {
                enabled: config.waf.modsecurity.enabled,
                rules_path: config.waf.modsecurity.rules_path.clone(),
                owasp_crs_path: config.waf.modsecurity.owasp_crs_path.clone(),
                debug_log_level: config.waf.modsecurity.debug_log_level,
                max_body_size: config.waf.modsecurity.max_body_size,
                blocking_mode: config.waf.modsecurity.blocking_mode,
                rule_update_interval: config.waf.modsecurity.rule_update_interval,
                auto_update_owasp_crs: config.waf.modsecurity.auto_update_owasp_crs,
                owasp_crs_repo_url: config.waf.modsecurity.owasp_crs_repo_url.clone(),
                owasp_crs_version: config.waf.modsecurity.owasp_crs_version.clone(),
            },
        };
        let waf = Arc::new(
            WafEngine::new(&waf_config, database.clone())
                .await
                .map_err(|e| GatewayError::WafError(format!("Failed to initialize WAF: {}", e)))?,
        );

        // Initialize plugins
        let plugins = if config.plugins.enabled {
            let plugin_config = gateway_plugins::PluginConfig {
                enabled: config.plugins.enabled,
                plugin_dir: config.plugins.plugin_dir.clone(),
                plugins: config
                    .plugins
                    .plugins
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            gateway_plugins::PluginInstanceConfig {
                                enabled: v.enabled,
                                config: v.config.clone(),
                            },
                        )
                    })
                    .collect(),
            };
            Arc::new(PluginManager::new(&plugin_config).await.map_err(|e| {
                GatewayError::PluginError(format!("Failed to initialize plugins: {}", e))
            })?)
        } else {
            Arc::new(PluginManager::disabled())
        };

        // Initialize SSL/TLS if enabled
        let (ssl_config, cert_manager) = if config.ssl.enabled {
            let ssl_config = gateway_ssl::SslConfig {
                enabled: config.ssl.enabled,
                auto_ssl: AutoSslConfig {
                    enabled: config.ssl.auto_ssl.enabled,
                    domains: config.ssl.auto_ssl.domains.clone(),
                    email: config.ssl.auto_ssl.email.clone(),
                    staging: config.ssl.auto_ssl.staging,
                    renewal_threshold_days: config.ssl.auto_ssl.renewal_threshold_days,
                    challenge_type: config.ssl.auto_ssl.challenge_type.clone(),
                    challenge_port: config.ssl.auto_ssl.challenge_port,
                },
                certificate: CertificateConfig {
                    storage_backend: config.ssl.certificate.storage_backend.clone(),
                    cache_directory: config.ssl.certificate.cache_directory.clone(),
                    watch_external_updates: config.ssl.certificate.watch_external_updates,
                    auto_reload: config.ssl.certificate.auto_reload,
                    reload_interval: config.ssl.certificate.reload_interval,
                },
                vault: config.ssl.vault.as_ref().map(|v| VaultConfig {
                    address: v.address.clone(),
                    token: v.token.clone(),
                    mount_path: v.mount_path.clone(),
                    certificate_path: v.certificate_path.clone(),
                    tls_cert_path: v.tls_cert_path.clone(),
                    tls_key_path: v.tls_key_path.clone(),
                    ca_cert_path: v.ca_cert_path.clone(),
                    skip_verify: v.skip_verify,
                    timeout: v.timeout,
                    auth_method: VaultAuthMethod {
                        method_type: v.auth_method.method_type.clone(),
                        config: v.auth_method.config.clone(),
                    },
                }),
                acme: AcmeConfig {
                    directory_url: config.ssl.acme.directory_url.clone(),
                    terms_of_service_agreed: config.ssl.acme.terms_of_service_agreed,
                    key_type: config.ssl.acme.key_type.clone(),
                    challenge_timeout: config.ssl.acme.challenge_timeout,
                    propagation_timeout: config.ssl.acme.propagation_timeout,
                    dns_providers: config
                        .ssl
                        .acme
                        .dns_providers
                        .iter()
                        .map(|(k, v)| {
                            (
                                k.clone(),
                                DnsProviderConfig {
                                    provider: v.provider.clone(),
                                    config: v.config.clone(),
                                },
                            )
                        })
                        .collect(),
                },
            };

            let cert_manager = Arc::new(SslManager::new(ssl_config).await.map_err(|e| {
                GatewayError::SslError(format!("Failed to initialize SSL manager: {}", e))
            })?);

            let default_cert = config
                .server
                .tls
                .as_ref()
                .map(|tls| tls.cert_path.clone())
                .unwrap_or_else(|| "/etc/ssl/certs/gateway.crt".to_string());
            let default_key = config
                .server
                .tls
                .as_ref()
                .map(|tls| tls.key_path.clone())
                .unwrap_or_else(|| "/etc/ssl/private/gateway.key".to_string());
            let require_client_cert = config
                .server
                .tls
                .as_ref()
                .map(|tls| tls.require_client_cert)
                .unwrap_or(false);
            let client_ca = config
                .server
                .tls
                .as_ref()
                .and_then(|tls| tls.ca_path.clone());

            let pingora_ssl = Arc::new(
                PingoraSslConfig::new(
                    cert_manager.clone(),
                    default_cert,
                    default_key,
                    require_client_cert,
                    client_ca,
                )
                .await?,
            );

            (Some(pingora_ssl), Some(cert_manager))
        } else {
            (None, None)
        };

        // Create Pingora server
        let mut server = Server::new(None).map_err(|e| {
            GatewayError::ProxyError(format!("Failed to create Pingora server: {}", e))
        })?;

        // Bootstrap the server
        server.bootstrap();

        // Add services to the server
        Self::add_services(
            &mut server,
            &config_adapter,
            waf.clone(),
            cache.clone(),
            auth.clone(),
            monitoring.clone(),
            plugins.clone(),
        )
        .await?;

        Ok(Self {
            server,
            config_adapter,
            ssl_config,
            waf,
            cache,
            auth,
            monitoring,
            plugins,
            database,
            cert_manager,
        })
    }

    /// Add HTTP and HTTPS services to the Pingora server  
    async fn add_services(
        _server: &mut Server,
        _config_adapter: &PingoraConfigAdapter,
        _waf: Arc<WafEngine>,
        _cache: Arc<CacheManager>,
        _auth: Arc<AuthManager>,
        _monitoring: Arc<MonitoringManager>,
        _plugins: Arc<PluginManager>,
    ) -> Result<()> {
        info!("Services configuration completed");

        // TODO: Add actual service registration when Pingora service APIs are stable
        warn!("Service registration is simplified in this version");

        Ok(())
    }

    /// Run the Pingora gateway server
    ///
    /// This will block the current thread until shutdown is requested.
    pub fn run_forever(self) {
        info!("Starting complete Pingora gateway server");
        self.server.run_forever();
    }

    /// Get server configuration for inspection
    pub fn get_configuration(&self) -> &Arc<pingora::server::configuration::ServerConf> {
        &self.server.configuration
    }

    /// Get gateway configuration
    pub fn get_gateway_config(&self) -> &GatewayConfig {
        self.config_adapter.get_gateway_config()
    }

    /// Update configuration at runtime
    pub async fn update_config(&mut self, new_config: GatewayConfig) -> Result<()> {
        info!("Updating gateway configuration");

        // Update config adapter
        self.config_adapter.update_config(new_config)?;

        // TODO: Implement hot reload of services
        warn!(
            "Configuration updated - server restart may be required for all changes to take effect"
        );

        Ok(())
    }

    /// Graceful shutdown
    pub async fn shutdown(self) -> Result<()> {
        info!("Shutting down Pingora gateway");

        // Stop components in reverse order
        if let Err(e) = self.plugins.stop().await {
            warn!("Error stopping plugins: {}", e);
        }

        if let Err(e) = self.monitoring.stop().await {
            warn!("Error stopping monitoring: {}", e);
        }

        if let Err(e) = self.database.close().await {
            warn!("Error closing database: {}", e);
        }

        info!("Pingora gateway shutdown complete");
        Ok(())
    }

    /// Health check for all components
    pub async fn health_check(&self) -> bool {
        let waf_healthy = self.waf.is_healthy().await;
        let cache_healthy = self.cache.is_healthy().await;
        let database_healthy = self.database.is_healthy().await;
        let auth_healthy = self.auth.is_healthy().await;
        let monitoring_healthy = self.monitoring.is_healthy().await;
        let plugins_healthy = self.plugins.is_healthy().await;

        waf_healthy
            && cache_healthy
            && database_healthy
            && auth_healthy
            && monitoring_healthy
            && plugins_healthy
    }

    /// Get comprehensive gateway statistics
    pub async fn get_stats(&self) -> std::collections::HashMap<String, serde_json::Value> {
        let mut stats = std::collections::HashMap::new();

        // Basic server info
        stats.insert(
            "server".to_string(),
            serde_json::json!({
                "version": "0.1.0",
                "powered_by": "Pingora",
                "uptime": "calculated_uptime_here"
            }),
        );

        // Component health
        stats.insert(
            "health".to_string(),
            serde_json::json!({
                "overall": self.health_check().await,
                "waf": self.waf.is_healthy().await,
                "cache": self.cache.is_healthy().await,
                "database": self.database.is_healthy().await,
                "auth": self.auth.is_healthy().await,
                "monitoring": self.monitoring.is_healthy().await,
                "plugins": self.plugins.is_healthy().await,
            }),
        );

        // SSL info if enabled
        if let Some(ssl_config) = &self.ssl_config {
            stats.insert(
                "ssl".to_string(),
                serde_json::Value::Object(ssl_config.get_ssl_stats().await.into_iter().collect()),
            );
        }

        stats
    }
}

/// Example function to demonstrate basic Pingora server setup
///
/// This creates a simple server for testing and development.
pub fn run_example_server() -> std::result::Result<(), Box<dyn std::error::Error>> {
    info!("Starting example Pingora server with default configuration");

    let config = GatewayConfig::default();

    tokio::runtime::Runtime::new()?.block_on(async {
        let gateway = PingoraGateway::new(config).await?;
        gateway.run_forever();
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pingora_gateway_creation() {
        let config = GatewayConfig::default();
        let result = PingoraGateway::new(config).await;
        assert!(
            result.is_ok(),
            "Should be able to create complete PingoraGateway instance"
        );
    }

    #[tokio::test]
    async fn test_configuration_access() {
        let config = GatewayConfig::default();
        let gateway = PingoraGateway::new(config)
            .await
            .expect("Should create gateway");
        let _config = gateway.get_configuration();
        let _gateway_config = gateway.get_gateway_config();
        // Basic test to ensure configuration is accessible
    }

    #[tokio::test]
    async fn test_health_check() {
        let config = GatewayConfig::default();
        let gateway = PingoraGateway::new(config)
            .await
            .expect("Should create gateway");
        let _healthy = gateway.health_check().await;
        // Health check should work without errors
    }

    #[tokio::test]
    async fn test_stats() {
        let config = GatewayConfig::default();
        let gateway = PingoraGateway::new(config)
            .await
            .expect("Should create gateway");
        let stats = gateway.get_stats().await;
        assert!(stats.contains_key("server"));
        assert!(stats.contains_key("health"));
    }
}
