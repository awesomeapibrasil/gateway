use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::GatewayConfig;
use crate::error::{GatewayError, Result};
use crate::proxy::GatewayProxy;
use crate::server::GatewayServer;
use crate::types::GatewayStats;

use gateway_auth::AuthManager;
use gateway_cache::CacheManager;
use gateway_database::DatabaseManager;
use gateway_monitoring::MonitoringManager;
use gateway_plugins::PluginManager;
use gateway_waf::WafEngine;

/// Main Gateway struct that coordinates all components
#[derive(Clone)]
pub struct Gateway {
    config: Arc<RwLock<GatewayConfig>>,
    server: Arc<GatewayServer>,
    proxy: Arc<GatewayProxy>,
    waf: Arc<WafEngine>,
    cache: Arc<CacheManager>,
    database: Arc<DatabaseManager>,
    auth: Arc<AuthManager>,
    monitoring: Arc<MonitoringManager>,
    plugins: Arc<PluginManager>,
    stats: Arc<RwLock<GatewayStats>>,
}

impl Gateway {
    /// Create a new Gateway instance with the given configuration
    pub async fn new(config: GatewayConfig) -> Result<Self> {
        info!("Initializing Gateway components");

        // Validate configuration
        config.validate()?;

        let config = Arc::new(RwLock::new(config));
        let config_clone = config.clone();
        let config_read = config_clone.read().await;

        // Initialize monitoring first as other components may need it
        let monitoring_config = gateway_monitoring::MonitoringConfig {
            enabled: config_read.monitoring.enabled,
            metrics_port: config_read.monitoring.metrics_port,
            log_level: config_read.monitoring.log_level.clone(),
            prometheus: gateway_monitoring::PrometheusConfig {
                enabled: config_read.monitoring.prometheus.enabled,
                endpoint: config_read.monitoring.prometheus.endpoint.clone(),
                namespace: config_read.monitoring.prometheus.namespace.clone(),
            },
            tracing: gateway_monitoring::TracingConfig {
                enabled: config_read.monitoring.tracing.enabled,
                endpoint: config_read.monitoring.tracing.endpoint.clone(),
                sample_rate: config_read.monitoring.tracing.sample_rate,
            },
            health_check_path: config_read.monitoring.health_check_path.clone(),
        };

        let monitoring = Arc::new(MonitoringManager::new(&monitoring_config).await.map_err(
            |e| GatewayError::MonitoringError(format!("Failed to initialize monitoring: {}", e)),
        )?);

        // Initialize database manager
        let database = if config_read.database.enabled {
            let db_config = gateway_database::DatabaseConfig {
                enabled: config_read.database.enabled,
                backend: config_read.database.backend.clone(),
                url: config_read.database.url.clone(),
                pool_size: config_read.database.pool_size,
                timeout: config_read.database.timeout,
                migrations_path: config_read.database.migrations_path.clone(),
                ssl_mode: config_read.database.ssl_mode.clone(),
            };
            Arc::new(DatabaseManager::new(&db_config).await.map_err(|e| {
                GatewayError::DatabaseError(format!("Failed to initialize database: {}", e))
            })?)
        } else {
            Arc::new(DatabaseManager::disabled())
        };

        // Initialize cache manager
        let cache_config = gateway_cache::CacheConfig {
            enabled: config_read.cache.enabled,
            backend: config_read.cache.backend.clone(),
            ttl: config_read.cache.ttl,
            max_size: config_read.cache.max_size,
            compression: config_read.cache.compression,
            redis: config_read
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

        // Initialize authentication manager
        let auth_config = gateway_auth::AuthConfig {
            enabled: config_read.auth.enabled,
            jwt_secret: config_read.auth.jwt_secret.clone(),
            jwt_expiry: config_read.auth.jwt_expiry,
            providers: config_read
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
            require_auth: config_read.auth.require_auth,
            public_paths: config_read.auth.public_paths.clone(),
        };
        let auth = Arc::new(
            AuthManager::new(&auth_config, database.clone())
                .await
                .map_err(|e| {
                    GatewayError::AuthError(format!("Failed to initialize auth: {}", e))
                })?,
        );

        // Initialize WAF engine
        let waf_config = gateway_waf::WafConfig {
            enabled: config_read.waf.enabled,
            rules_path: config_read.waf.rules_path.clone(),
            rate_limiting: gateway_waf::RateLimitConfig {
                enabled: config_read.waf.rate_limiting.enabled,
                requests_per_minute: config_read.waf.rate_limiting.requests_per_minute,
                burst_limit: config_read.waf.rate_limiting.burst_limit,
                window_size: config_read.waf.rate_limiting.window_size,
                storage_backend: config_read.waf.rate_limiting.storage_backend.clone(),
            },
            ip_whitelist: config_read.waf.ip_whitelist.clone(),
            ip_blacklist: config_read.waf.ip_blacklist.clone(),
            blocked_headers: config_read.waf.blocked_headers.clone(),
            blocked_user_agents: config_read.waf.blocked_user_agents.clone(),
            max_request_size: config_read.waf.max_request_size,
            block_malicious_ips: config_read.waf.block_malicious_ips,
            modsecurity: gateway_waf::ModSecurityConfig {
                enabled: config_read.waf.modsecurity.enabled,
                rules_path: config_read.waf.modsecurity.rules_path.clone(),
                owasp_crs_path: config_read.waf.modsecurity.owasp_crs_path.clone(),
                debug_log_level: config_read.waf.modsecurity.debug_log_level,
                max_body_size: config_read.waf.modsecurity.max_body_size,
                blocking_mode: config_read.waf.modsecurity.blocking_mode,
                rule_update_interval: config_read.waf.modsecurity.rule_update_interval,
            },
        };
        let waf = Arc::new(
            WafEngine::new(&waf_config, database.clone())
                .await
                .map_err(|e| GatewayError::WafError(format!("Failed to initialize WAF: {}", e)))?,
        );

        // Initialize plugin manager
        let plugins = if config_read.plugins.enabled {
            let plugin_config = gateway_plugins::PluginConfig {
                enabled: config_read.plugins.enabled,
                plugin_dir: config_read.plugins.plugin_dir.clone(),
                plugins: config_read
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

        // Initialize proxy
        let proxy = Arc::new(
            GatewayProxy::new(
                &config_read.upstream,
                waf.clone(),
                cache.clone(),
                auth.clone(),
                monitoring.clone(),
                plugins.clone(),
            )
            .await
            .map_err(|e| GatewayError::ProxyError(format!("Failed to initialize proxy: {}", e)))?,
        );

        // Initialize server
        let server = Arc::new(
            GatewayServer::new(&config_read.server, proxy.clone(), monitoring.clone())
                .await
                .map_err(|e| {
                    GatewayError::ProxyError(format!("Failed to initialize server: {}", e))
                })?,
        );

        // Initialize stats
        let stats = Arc::new(RwLock::new(GatewayStats::default()));

        drop(config_read);

        let gateway = Self {
            config,
            server,
            proxy,
            waf,
            cache,
            database,
            auth,
            monitoring,
            plugins,
            stats,
        };

        info!("Gateway components initialized successfully");
        Ok(gateway)
    }

    /// Run the gateway server
    pub async fn run(&self) -> Result<()> {
        info!("Starting Gateway server");

        // Start monitoring
        if let Err(e) = self.monitoring.start().await {
            warn!("Failed to start monitoring: {}", e);
        }

        // Start plugin manager
        if let Err(e) = self.plugins.start().await {
            warn!("Failed to start plugins: {}", e);
        }

        // Run the server (this will block until shutdown)
        match self.server.run().await {
            Ok(_) => {
                info!("Gateway server started successfully");
                Ok(())
            }
            Err(e) => {
                error!("Gateway server failed: {}", e);
                Err(GatewayError::ProxyError(format!("Server failed: {}", e)))
            }
        }
    }

    /// Graceful shutdown of the gateway
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down Gateway");

        // Stop plugins
        if let Err(e) = self.plugins.stop().await {
            warn!("Error stopping plugins: {}", e);
        }

        // Stop monitoring
        if let Err(e) = self.monitoring.stop().await {
            warn!("Error stopping monitoring: {}", e);
        }

        // Close database connections
        if let Err(e) = self.database.close().await {
            warn!("Error closing database: {}", e);
        }

        // Stop server
        if let Err(e) = self.server.shutdown().await {
            warn!("Error stopping server: {}", e);
        }

        info!("Gateway shutdown complete");
        Ok(())
    }

    /// Get current gateway statistics
    pub async fn get_stats(&self) -> GatewayStats {
        self.stats.read().await.clone()
    }

    /// Update configuration at runtime (simplified implementation)
    pub async fn update_config(&self, new_config: GatewayConfig) -> Result<()> {
        info!("Updating Gateway configuration");

        // Validate new configuration
        new_config.validate()?;

        let mut config = self.config.write().await;
        *config = new_config;

        info!("Configuration updated successfully");
        Ok(())
    }

    /// Get the current configuration
    pub async fn get_config(&self) -> GatewayConfig {
        self.config.read().await.clone()
    }

    /// Check if the gateway is healthy
    pub async fn health_check(&self) -> bool {
        // Check all components
        let waf_healthy = self.waf.is_healthy().await;
        let cache_healthy = self.cache.is_healthy().await;
        let database_healthy = self.database.is_healthy().await;
        let auth_healthy = self.auth.is_healthy().await;
        let monitoring_healthy = self.monitoring.is_healthy().await;
        let plugins_healthy = self.plugins.is_healthy().await;
        let proxy_healthy = self.proxy.is_healthy().await;

        waf_healthy
            && cache_healthy
            && database_healthy
            && auth_healthy
            && monitoring_healthy
            && plugins_healthy
            && proxy_healthy
    }
}

impl Default for GatewayStats {
    fn default() -> Self {
        use std::time::Duration;

        Self {
            total_requests: 0,
            total_responses: 0,
            active_connections: 0,
            cache_hits: 0,
            cache_misses: 0,
            waf_blocks: 0,
            rate_limit_blocks: 0,
            backend_errors: 0,
            average_response_time: Duration::from_millis(0),
            uptime: Duration::from_secs(0),
            memory_usage: 0,
            cpu_usage: 0.0,
        }
    }
}
