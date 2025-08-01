//! Pingora HTTP Service Integration
//!
//! This module provides a basic HTTP service implementation using Pingora that integrates
//! with all gateway components including WAF, authentication, caching, monitoring, and plugins.

use std::sync::Arc;
use gateway_auth::AuthManager;
use gateway_cache::CacheManager;
use gateway_monitoring::MonitoringManager;
use gateway_plugins::PluginManager;
use gateway_waf::WafEngine;

/// Basic HTTP service with gateway integration
pub struct PingoraHttpService {
    waf: Arc<WafEngine>,
    cache: Arc<CacheManager>,
    auth: Arc<AuthManager>,
    monitoring: Arc<MonitoringManager>,
    plugins: Arc<PluginManager>,
}

impl PingoraHttpService {
    /// Create a new HTTP service with all gateway components
    pub fn new(
        waf: Arc<WafEngine>,
        cache: Arc<CacheManager>,
        auth: Arc<AuthManager>,
        monitoring: Arc<MonitoringManager>,
        plugins: Arc<PluginManager>,
    ) -> Self {
        Self {
            waf,
            cache,
            auth,
            monitoring,
            plugins,
        }
    }

    /// Check if all components are healthy
    pub async fn health_check(&self) -> bool {
        let waf_healthy = self.waf.is_healthy().await;
        let cache_healthy = self.cache.is_healthy().await;
        let auth_healthy = self.auth.is_healthy().await;
        let monitoring_healthy = self.monitoring.is_healthy().await;
        let plugins_healthy = self.plugins.is_healthy().await;

        waf_healthy && cache_healthy && auth_healthy && monitoring_healthy && plugins_healthy
    }

    /// Get service statistics
    pub async fn get_stats(&self) -> std::collections::HashMap<String, serde_json::Value> {
        let mut stats = std::collections::HashMap::new();

        stats.insert(
            "healthy".to_string(),
            serde_json::Value::Bool(self.health_check().await),
        );
        stats.insert(
            "components".to_string(),
            serde_json::json!({
                "waf": "enabled",
                "cache": "enabled",
                "auth": "enabled",
                "monitoring": "enabled",
                "plugins": "enabled"
            }),
        );

        stats
    }
}
