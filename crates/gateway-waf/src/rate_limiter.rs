use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use dashmap::DashMap;

use crate::{RequestContext, RateLimitConfig, WafError, Result};
use gateway_database::DatabaseManager;

/// Rate limiting key for identifying clients
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum RateLimitKey {
    Ip(std::net::IpAddr),
    UserAgent(String),
    Header(String, String),
    Composite(Vec<String>),
}

impl RateLimitKey {
    /// Extract rate limit key from request context
    pub fn from_request(request: &RequestContext, key_type: &str) -> Self {
        match key_type {
            "ip" => RateLimitKey::Ip(request.client_ip),
            "user_agent" => RateLimitKey::UserAgent(
                request.user_agent.clone().unwrap_or_default()
            ),
            key if key.starts_with("header:") => {
                let header_name = &key[7..];
                let header_value = request.headers.get(header_name).cloned().unwrap_or_default();
                RateLimitKey::Header(header_name.to_string(), header_value)
            }
            _ => RateLimitKey::Ip(request.client_ip), // Default to IP
        }
    }

    /// Convert key to string for storage
    pub fn to_string(&self) -> String {
        match self {
            RateLimitKey::Ip(ip) => format!("ip:{}", ip),
            RateLimitKey::UserAgent(ua) => format!("ua:{}", ua),
            RateLimitKey::Header(name, value) => format!("header:{}:{}", name, value),
            RateLimitKey::Composite(parts) => format!("composite:{}", parts.join(":")),
        }
    }
}

/// Rate limit entry tracking requests for a key
#[derive(Debug, Clone)]
struct RateLimitEntry {
    requests: u32,
    window_start: SystemTime,
    last_request: SystemTime,
}

/// Rate limiter implementation
pub struct RateLimiter {
    config: Arc<RwLock<RateLimitConfig>>,
    memory_store: Arc<DashMap<String, RateLimitEntry>>,
    database: Arc<DatabaseManager>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub async fn new(config: &RateLimitConfig, database: Arc<DatabaseManager>) -> Result<Self> {
        Ok(Self {
            config: Arc::new(RwLock::new(config.clone())),
            memory_store: Arc::new(DashMap::new()),
            database,
        })
    }

    /// Check if a request should be rate limited
    pub async fn check_request(&self, request: &RequestContext) -> Result<bool> {
        let config = self.config.read().await;
        
        if !config.enabled {
            return Ok(true); // Allow if rate limiting is disabled
        }

        let key = RateLimitKey::from_request(request, "ip");
        let key_str = key.to_string();
        
        let now = SystemTime::now();
        
        // Get or create entry
        let mut entry = self.memory_store.entry(key_str.clone())
            .or_insert_with(|| RateLimitEntry {
                requests: 0,
                window_start: now,
                last_request: now,
            });

        // Check if we need to reset the window
        let window_elapsed = now.duration_since(entry.window_start)
            .unwrap_or(Duration::ZERO);
        
        if window_elapsed >= config.window_size {
            // Reset the window
            entry.requests = 0;
            entry.window_start = now;
        }

        // Check rate limits
        if entry.requests >= config.requests_per_minute {
            // Check burst limit
            let time_since_last = now.duration_since(entry.last_request)
                .unwrap_or(Duration::ZERO);
            
            if entry.requests >= config.burst_limit || time_since_last < Duration::from_secs(1) {
                return Ok(false); // Rate limited
            }
        }

        // Update entry
        entry.requests += 1;
        entry.last_request = now;

        // Store in database if configured
        if let Err(e) = self.store_rate_limit_data(&key_str, &entry).await {
            tracing::warn!("Failed to store rate limit data: {}", e);
        }

        Ok(true) // Allow request
    }

    /// Store rate limit data in database
    async fn store_rate_limit_data(&self, _key: &str, _entry: &RateLimitEntry) -> Result<()> {
        // Placeholder for database storage
        // In a real implementation, this would store the rate limit data
        // in the configured database backend for distributed rate limiting
        Ok(())
    }

    /// Update rate limiter configuration
    pub async fn update_config(&self, new_config: &RateLimitConfig) -> Result<()> {
        let mut config = self.config.write().await;
        *config = new_config.clone();
        Ok(())
    }

    /// Check if rate limiter is healthy
    pub async fn is_healthy(&self) -> bool {
        // Simple health check - ensure we can read config
        self.config.read().await.enabled || true
    }

    /// Clean up old entries
    pub async fn cleanup_old_entries(&self) {
        let config = self.config.read().await;
        let now = SystemTime::now();
        let cleanup_threshold = config.window_size * 2;

        // Remove entries older than threshold
        self.memory_store.retain(|_, entry| {
            now.duration_since(entry.last_request)
                .map(|elapsed| elapsed < cleanup_threshold)
                .unwrap_or(false)
        });
    }

    /// Get rate limit statistics
    pub async fn get_stats(&self) -> HashMap<String, u32> {
        let mut stats = HashMap::new();
        
        let total_entries = self.memory_store.len();
        stats.insert("total_tracked_keys".to_string(), total_entries as u32);
        
        let active_entries = self.memory_store.iter()
            .filter(|entry| {
                SystemTime::now().duration_since(entry.last_request)
                    .map(|elapsed| elapsed < Duration::from_secs(60))
                    .unwrap_or(false)
            })
            .count();
        
        stats.insert("active_keys".to_string(), active_entries as u32);
        
        stats
    }

    /// Get rate limit info for a specific key
    pub async fn get_key_info(&self, key: &RateLimitKey) -> Option<(u32, SystemTime)> {
        let key_str = key.to_string();
        self.memory_store.get(&key_str)
            .map(|entry| (entry.requests, entry.window_start))
    }

    /// Reset rate limit for a specific key
    pub async fn reset_key(&self, key: &RateLimitKey) -> bool {
        let key_str = key.to_string();
        self.memory_store.remove(&key_str).is_some()
    }

    /// Add a custom rate limit rule
    pub async fn add_custom_limit(&self, _key: RateLimitKey, _limit: u32, _window: Duration) -> Result<()> {
        // Placeholder for custom rate limit rules
        // In a real implementation, this would allow setting different limits
        // for different keys or patterns
        Ok(())
    }
}

impl Default for RateLimitEntry {
    fn default() -> Self {
        let now = SystemTime::now();
        Self {
            requests: 0,
            window_start: now,
            last_request: now,
        }
    }
}