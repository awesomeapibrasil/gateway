use dashmap::DashMap;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

use crate::{RateLimitConfig, RequestContext, Result};
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
            "user_agent" => RateLimitKey::UserAgent(request.user_agent.clone().unwrap_or_default()),
            key if key.starts_with("header:") => {
                let header_name = &key[7..];
                let header_value = request
                    .headers
                    .get(header_name)
                    .cloned()
                    .unwrap_or_default();
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

/// Custom rate limit rule
#[derive(Debug, Clone)]
pub struct CustomRateLimit {
    pub limit: u32,
    pub window: Duration,
    pub created_at: SystemTime,
}

/// Rate limiter implementation
#[allow(dead_code)]
pub struct RateLimiter {
    config: Arc<RwLock<RateLimitConfig>>,
    memory_store: Arc<DashMap<String, RateLimitEntry>>,
    custom_limits: Arc<DashMap<String, CustomRateLimit>>,
    database: Arc<DatabaseManager>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub async fn new(config: &RateLimitConfig, database: Arc<DatabaseManager>) -> Result<Self> {
        Ok(Self {
            config: Arc::new(RwLock::new(config.clone())),
            memory_store: Arc::new(DashMap::new()),
            custom_limits: Arc::new(DashMap::new()),
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

        // First, try to load from database for distributed rate limiting
        let mut entry = if let Some(db_entry) = self.load_rate_limit_data(&key_str).await {
            // Use database entry and sync with memory store
            self.memory_store.insert(key_str.clone(), db_entry.clone());
            db_entry
        } else {
            // Get or create memory entry
            self.memory_store
                .entry(key_str.clone())
                .or_insert_with(|| RateLimitEntry {
                    requests: 0,
                    window_start: now,
                    last_request: now,
                })
                .clone()
        };

        // Check if we need to reset the window
        let (requests_limit, burst_limit, window_size) =
            if let Some(custom_limit) = self.custom_limits.get(&key_str) {
                // Use custom limits for this key
                (
                    custom_limit.limit,
                    custom_limit.limit * 2,
                    custom_limit.window,
                ) // Burst is 2x the limit
            } else {
                // Use default config limits
                (
                    config.requests_per_minute,
                    config.burst_limit,
                    config.window_size,
                )
            };

        let window_elapsed = now
            .duration_since(entry.window_start)
            .unwrap_or(Duration::ZERO);

        if window_elapsed >= window_size {
            // Reset the window
            entry.requests = 0;
            entry.window_start = now;
        }

        // Check rate limits (using custom or default limits)
        if entry.requests >= requests_limit {
            // Check burst limit
            let time_since_last = now
                .duration_since(entry.last_request)
                .unwrap_or(Duration::ZERO);

            if entry.requests >= burst_limit || time_since_last < Duration::from_secs(1) {
                return Ok(false); // Rate limited
            }
        }

        // Update entry
        entry.requests += 1;
        entry.last_request = now;

        // Update memory store
        self.memory_store.insert(key_str.clone(), entry.clone());

        // Store in database if configured (for distributed rate limiting)
        if let Err(e) = self.store_rate_limit_data(&key_str, &entry).await {
            tracing::warn!("Failed to store rate limit data: {}", e);
        }

        Ok(true) // Allow request
    }

    /// Store rate limit data in database
    async fn store_rate_limit_data(&self, key: &str, entry: &RateLimitEntry) -> Result<()> {
        // Store in database for distributed rate limiting
        if let Some(pool) = self.database.get_pool() {
            // Generate a hash of the key for efficient indexing
            let mut hasher = Sha256::new();
            hasher.update(key.as_bytes());
            let key_hash = format!("{:x}", hasher.finalize());

            // Parse the key to extract type and value
            let (key_type, key_value) = self.parse_rate_limit_key(key);

            // Convert SystemTime to chrono DateTime for database storage
            let window_start = chrono::DateTime::<chrono::Utc>::from(entry.window_start);
            let last_request = chrono::DateTime::<chrono::Utc>::from(entry.last_request);

            let result = sqlx::query(
                r#"
                INSERT INTO rate_limit_entries (
                    key_hash, key_type, key_value, requests, window_start, last_request
                ) VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (key_hash) DO UPDATE SET
                    requests = EXCLUDED.requests,
                    window_start = EXCLUDED.window_start,
                    last_request = EXCLUDED.last_request,
                    updated_at = NOW()
                "#,
            )
            .bind(&key_hash)
            .bind(&key_type)
            .bind(&key_value)
            .bind(entry.requests as i32)
            .bind(window_start.to_rfc3339())
            .bind(last_request.to_rfc3339())
            .execute(pool)
            .await;

            match result {
                Ok(_) => {
                    tracing::debug!(
                        "Successfully stored rate limit data in database for key: {}",
                        key
                    );
                    Ok(())
                }
                Err(e) => {
                    tracing::warn!("Failed to store rate limit data in database: {}", e);
                    // Don't fail the request if database storage fails
                    Ok(())
                }
            }
        } else {
            // Database not available, continue without distributed storage
            tracing::debug!("Database not available for rate limit storage");
            Ok(())
        }
    }

    /// Parse rate limit key to extract type and value for database storage
    fn parse_rate_limit_key(&self, key: &str) -> (String, String) {
        // Rate limit keys are typically in format: "type:value" or just "value" for IP
        if let Some(colon_pos) = key.find(':') {
            let key_type = key[..colon_pos].to_string();
            let key_value = key[colon_pos + 1..].to_string();
            (key_type, key_value)
        } else {
            // Assume it's an IP address if no type prefix
            ("ip".to_string(), key.to_string())
        }
    }

    /// Load rate limit data from database (for distributed rate limiting)
    async fn load_rate_limit_data(&self, key: &str) -> Option<RateLimitEntry> {
        if let Some(pool) = self.database.get_pool() {
            // Generate the same hash for lookup
            let mut hasher = Sha256::new();
            hasher.update(key.as_bytes());
            let key_hash = format!("{:x}", hasher.finalize());

            let result = sqlx::query(
                "SELECT requests, window_start, last_request FROM rate_limit_entries WHERE key_hash = $1"
            )
            .bind(&key_hash)
            .fetch_optional(pool)
            .await;

            match result {
                Ok(Some(row)) => {
                    // Parse the data from database
                    if let (Ok(requests), Ok(window_start_str), Ok(last_request_str)) = (
                        row.try_get::<i32, _>("requests"),
                        row.try_get::<String, _>("window_start"),
                        row.try_get::<String, _>("last_request"),
                    ) {
                        // Parse timestamps
                        if let (Ok(window_start_dt), Ok(last_request_dt)) = (
                            chrono::DateTime::parse_from_rfc3339(&window_start_str),
                            chrono::DateTime::parse_from_rfc3339(&last_request_str),
                        ) {
                            let entry = RateLimitEntry {
                                requests: requests as u32,
                                window_start: window_start_dt.with_timezone(&chrono::Utc).into(),
                                last_request: last_request_dt.with_timezone(&chrono::Utc).into(),
                            };
                            tracing::debug!(
                                "Loaded rate limit data from database for key: {}",
                                key
                            );
                            return Some(entry);
                        }
                    }
                    tracing::warn!(
                        "Failed to parse rate limit data from database for key: {}",
                        key
                    );
                }
                Ok(None) => {
                    tracing::debug!("No rate limit data found in database for key: {}", key);
                }
                Err(e) => {
                    tracing::warn!("Failed to load rate limit data from database: {}", e);
                }
            }
        }
        None
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

        let active_entries = self
            .memory_store
            .iter()
            .filter(|entry| {
                SystemTime::now()
                    .duration_since(entry.last_request)
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
        self.memory_store
            .get(&key_str)
            .map(|entry| (entry.requests, entry.window_start))
    }

    /// Reset rate limit for a specific key
    pub async fn reset_key(&self, key: &RateLimitKey) -> bool {
        let key_str = key.to_string();
        self.memory_store.remove(&key_str).is_some()
    }

    /// Add a custom rate limit rule
    pub async fn add_custom_limit(
        &self,
        key: RateLimitKey,
        limit: u32,
        window: Duration,
    ) -> Result<()> {
        let key_str = key.to_string();
        let custom_limit = CustomRateLimit {
            limit,
            window,
            created_at: SystemTime::now(),
        };

        // Store the custom limit in memory
        self.custom_limits
            .insert(key_str.clone(), custom_limit.clone());

        // Optionally store in database for persistence across restarts
        if let Some(pool) = self.database.get_pool() {
            // Generate a hash of the key for efficient indexing
            let mut hasher = Sha256::new();
            hasher.update(format!("custom:{}", key_str).as_bytes());
            let key_hash = format!("{:x}", hasher.finalize());

            let (key_type, _key_value) = self.parse_rate_limit_key(&key_str);
            let created_at = chrono::DateTime::<chrono::Utc>::from(custom_limit.created_at);

            let result = sqlx::query(
                r#"
                INSERT INTO rate_limit_entries (
                    key_hash, key_type, key_value, requests, window_start, last_request
                ) VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (key_hash) DO UPDATE SET
                    requests = EXCLUDED.requests,
                    updated_at = NOW()
                "#,
            )
            .bind(&key_hash)
            .bind(format!("custom:{key_type}"))
            .bind(format!("limit:{limit}:window:{}", window.as_secs()))
            .bind(0i32) // Initial request count
            .bind(created_at.to_rfc3339())
            .bind(created_at.to_rfc3339())
            .execute(pool)
            .await;

            match result {
                Ok(_) => {
                    tracing::info!(
                        "Successfully stored custom rate limit rule in database for key: {}",
                        key_str
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to store custom rate limit rule in database: {}", e);
                    // Don't fail if database storage fails
                }
            }
        }

        tracing::info!(
            "Added custom rate limit rule: {} requests per {:?} for key: {}",
            limit,
            window,
            key_str
        );
        Ok(())
    }

    /// Remove a custom rate limit rule
    pub async fn remove_custom_limit(&self, key: &RateLimitKey) -> bool {
        let key_str = key.to_string();

        // Remove from memory
        let was_present = self.custom_limits.remove(&key_str).is_some();

        // Remove from database if present
        if let Some(pool) = self.database.get_pool() {
            let mut hasher = Sha256::new();
            hasher.update(format!("custom:{}", key_str).as_bytes());
            let key_hash = format!("{:x}", hasher.finalize());

            let _result = sqlx::query("DELETE FROM rate_limit_entries WHERE key_hash = $1")
                .bind(&key_hash)
                .execute(pool)
                .await;
        }

        if was_present {
            tracing::info!("Removed custom rate limit rule for key: {}", key_str);
        }

        was_present
    }

    /// Get current custom rate limit rules
    pub fn list_custom_limits(&self) -> HashMap<String, CustomRateLimit> {
        self.custom_limits
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
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
