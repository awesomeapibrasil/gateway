use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::GatewayConfig;
use crate::error::{GatewayError, Result};
use crate::proxy::GatewayProxy;
use crate::server::GatewayServer;
use crate::types::GatewayStats;

use gateway_waf::WafEngine;
use gateway_cache::CacheManager;
use gateway_database::DatabaseManager;
use gateway_auth::AuthManager;
use gateway_monitoring::MonitoringManager;
use gateway_plugins::PluginManager;

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
        let monitoring = Arc::new(
            MonitoringManager::new(&config_read.monitoring)
                .await
                .map_err(|e| GatewayError::MonitoringError(format!("Failed to initialize monitoring: {}", e)))?
        );

        // Initialize database manager
        let database = if config_read.database.enabled {
            Arc::new(
                DatabaseManager::new(&config_read.database)
                    .await
                    .map_err(|e| GatewayError::DatabaseError(format!("Failed to initialize database: {}", e)))?
            )
        } else {
            Arc::new(DatabaseManager::disabled())
        };

        // Initialize cache manager
        let cache = Arc::new(
            CacheManager::new(&config_read.cache, database.clone())
                .await
                .map_err(|e| GatewayError::CacheError(format!("Failed to initialize cache: {}", e)))?
        );

        // Initialize authentication manager
        let auth = Arc::new(
            AuthManager::new(&config_read.auth, database.clone())
                .await
                .map_err(|e| GatewayError::AuthError(format!("Failed to initialize auth: {}", e)))?
        );

        // Initialize WAF engine
        let waf = Arc::new(
            WafEngine::new(&config_read.waf, database.clone())
                .await
                .map_err(|e| GatewayError::WafError(format!("Failed to initialize WAF: {}", e)))?
        );

        // Initialize plugin manager
        let plugins = if config_read.plugins.enabled {
            Arc::new(
                PluginManager::new(&config_read.plugins)
                    .await
                    .map_err(|e| GatewayError::PluginError(format!("Failed to initialize plugins: {}", e)))?
            )
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
            ).await
            .map_err(|e| GatewayError::ProxyError(format!("Failed to initialize proxy: {}", e)))?
        );

        // Initialize server
        let server = Arc::new(
            GatewayServer::new(&config_read.server, proxy.clone(), monitoring.clone())
                .await
                .map_err(|e| GatewayError::ProxyError(format!("Failed to initialize server: {}", e)))?
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

    /// Update configuration at runtime
    pub async fn update_config(&self, new_config: GatewayConfig) -> Result<()> {
        info!("Updating Gateway configuration");

        // Validate new configuration
        new_config.validate()?;

        let mut config = self.config.write().await;
        let old_config = config.clone();

        // Check what changed and update components accordingly
        if old_config.waf != new_config.waf {
            if let Err(e) = self.waf.update_config(&new_config.waf).await {
                error!("Failed to update WAF config: {}", e);
                return Err(GatewayError::WafError(format!("Config update failed: {}", e)));
            }
        }

        if old_config.cache != new_config.cache {
            if let Err(e) = self.cache.update_config(&new_config.cache).await {
                error!("Failed to update cache config: {}", e);
                return Err(GatewayError::CacheError(format!("Config update failed: {}", e)));
            }
        }

        if old_config.auth != new_config.auth {
            if let Err(e) = self.auth.update_config(&new_config.auth).await {
                error!("Failed to update auth config: {}", e);
                return Err(GatewayError::AuthError(format!("Config update failed: {}", e)));
            }
        }

        if old_config.monitoring != new_config.monitoring {
            if let Err(e) = self.monitoring.update_config(&new_config.monitoring).await {
                error!("Failed to update monitoring config: {}", e);
                return Err(GatewayError::MonitoringError(format!("Config update failed: {}", e)));
            }
        }

        if old_config.plugins != new_config.plugins {
            if let Err(e) = self.plugins.update_config(&new_config.plugins).await {
                error!("Failed to update plugins config: {}", e);
                return Err(GatewayError::PluginError(format!("Config update failed: {}", e)));
            }
        }

        if old_config.upstream != new_config.upstream {
            if let Err(e) = self.proxy.update_config(&new_config.upstream).await {
                error!("Failed to update proxy config: {}", e);
                return Err(GatewayError::ProxyError(format!("Config update failed: {}", e)));
            }
        }

        // Update the stored configuration
        *config = new_config;

        info!("Gateway configuration updated successfully");
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

        waf_healthy && cache_healthy && database_healthy && auth_healthy 
            && monitoring_healthy && plugins_healthy && proxy_healthy
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