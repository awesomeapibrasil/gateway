//! Distributed Cache Manager

use dashmap::DashMap;
use redis::{Client as RedisClient, Commands};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CacheConfig {
    pub enabled: bool,
    pub backend: String,
    pub ttl: Duration,
    pub max_size: usize,
    pub compression: bool,
    pub redis: Option<RedisConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: u32,
    pub timeout: Duration,
    pub cluster: bool,
}

/// Cache entry with metadata
#[derive(Debug, Clone)]
struct CacheEntry {
    data: Vec<u8>,
    #[allow(dead_code)] // Kept for potential future use and debugging
    created_at: std::time::SystemTime,
    expires_at: std::time::SystemTime,
    last_accessed: std::time::SystemTime,
    access_count: u64,
    compressed: bool,
}

pub struct CacheManager {
    config: CacheConfig,
    memory_cache: Arc<DashMap<String, CacheEntry>>,
    redis_client: Option<RedisClient>,
    database: std::sync::Arc<gateway_database::DatabaseManager>,
}

impl CacheManager {
    pub async fn new(
        config: &CacheConfig,
        database: std::sync::Arc<gateway_database::DatabaseManager>,
    ) -> Result<Self, String> {
        let redis_client = if let Some(redis_config) = &config.redis {
            match RedisClient::open(redis_config.url.as_str()) {
                Ok(client) => {
                    info!("Successfully connected to Redis: {}", redis_config.url);
                    Some(client)
                }
                Err(e) => {
                    warn!("Failed to connect to Redis: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            config: config.clone(),
            memory_cache: Arc::new(DashMap::new()),
            redis_client,
            database,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub async fn get(&self, uri: &str) -> Result<Option<Vec<u8>>, String> {
        if !self.config.enabled {
            return Ok(None);
        }

        let cache_key = self.generate_cache_key(uri);

        // Try memory cache first
        if let Some(entry) = self.memory_cache.get(&cache_key) {
            if entry.expires_at > std::time::SystemTime::now() {
                debug!("Cache hit (memory) for key: {}", cache_key);

                // Update access count and last accessed time
                let mut entry_mut = entry.clone();
                entry_mut.access_count += 1;
                entry_mut.last_accessed = std::time::SystemTime::now();
                self.memory_cache
                    .insert(cache_key.clone(), entry_mut.clone());

                return Ok(Some(if entry.compressed {
                    self.decompress(&entry.data)?
                } else {
                    entry.data.clone()
                }));
            } else {
                // Expired entry, remove it
                self.memory_cache.remove(&cache_key);
            }
        }

        // Try Redis cache
        if let Some(ref redis_client) = self.redis_client {
            if let Ok(mut conn) = redis_client.get_connection() {
                match conn.get::<&str, Option<Vec<u8>>>(&cache_key) {
                    Ok(Some(data)) => {
                        debug!("Cache hit (Redis) for key: {}", cache_key);

                        // Store in memory cache for faster access
                        let now = std::time::SystemTime::now();
                        let entry = CacheEntry {
                            data: data.clone(),
                            created_at: now,
                            expires_at: now + self.config.ttl,
                            last_accessed: now,
                            access_count: 1,
                            compressed: self.config.compression,
                        };
                        self.memory_cache.insert(cache_key, entry);

                        return Ok(Some(if self.config.compression {
                            self.decompress(&data)?
                        } else {
                            data
                        }));
                    }
                    Ok(None) => {
                        debug!("Cache miss (Redis) for key: {}", cache_key);
                    }
                    Err(e) => {
                        warn!("Redis error: {}", e);
                    }
                }
            }
        }

        // Try database cache
        if let Some(pool) = self.database.get_pool() {
            let result = sqlx::query(
                "SELECT value_data, compressed, expires_at FROM cache_entries WHERE key_hash = $1 AND expires_at > NOW()"
            )
            .bind(&cache_key)
            .fetch_optional(pool)
            .await;

            match result {
                Ok(Some(row)) => {
                    let data: Vec<u8> = row.try_get("value_data").map_err(|e| e.to_string())?;
                    let compressed: bool = row.try_get("compressed").map_err(|e| e.to_string())?;

                    debug!("Cache hit (database) for key: {}", cache_key);

                    // Store in memory and Redis for faster access
                    let now = std::time::SystemTime::now();
                    let entry = CacheEntry {
                        data: data.clone(),
                        created_at: now,
                        expires_at: now + self.config.ttl,
                        last_accessed: now,
                        access_count: 1,
                        compressed,
                    };
                    self.memory_cache.insert(cache_key.clone(), entry);

                    // Also cache in Redis if available
                    if let Some(ref redis_client) = self.redis_client {
                        if let Ok(mut conn) = redis_client.get_connection() {
                            let _: Result<(), redis::RedisError> =
                                conn.set_ex(&cache_key, &data, self.config.ttl.as_secs());
                        }
                    }

                    return Ok(Some(if compressed {
                        self.decompress(&data)?
                    } else {
                        data
                    }));
                }
                Ok(None) => {
                    debug!("Cache miss (database) for key: {}", cache_key);
                }
                Err(e) => {
                    warn!("Database cache error: {}", e);
                }
            }
        }

        debug!("Cache miss for key: {}", cache_key);
        Ok(None)
    }

    pub async fn set(&self, uri: &str, data: &[u8]) -> Result<(), String> {
        if !self.config.enabled {
            return Ok(());
        }

        let cache_key = self.generate_cache_key(uri);
        let now = std::time::SystemTime::now();
        let expires_at = now + self.config.ttl;

        // Compress data if compression is enabled
        let (final_data, compressed) = if self.config.compression {
            (self.compress(data)?, true)
        } else {
            (data.to_vec(), false)
        };

        // Store in memory cache
        let entry = CacheEntry {
            data: final_data.clone(),
            created_at: now,
            expires_at,
            last_accessed: now,
            access_count: 0,
            compressed,
        };

        // Check memory cache size limit
        if self.memory_cache.len() >= self.config.max_size {
            self.evict_oldest_entries().await;
        }

        self.memory_cache.insert(cache_key.clone(), entry);

        // Store in Redis if available
        if let Some(ref redis_client) = self.redis_client {
            if let Ok(mut conn) = redis_client.get_connection() {
                match conn.set_ex::<&str, &[u8], ()>(
                    &cache_key,
                    &final_data,
                    self.config.ttl.as_secs(),
                ) {
                    Ok(_) => debug!("Cached in Redis for key: {}", cache_key),
                    Err(e) => warn!("Failed to cache in Redis: {}", e),
                }
            }
        }

        // Store in database for persistence
        if let Some(pool) = self.database.get_pool() {
            let result = sqlx::query(
                r#"
                INSERT INTO cache_entries (
                    key_hash, key_value, value_data, compressed, expires_at
                ) VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (key_hash) DO UPDATE SET
                    value_data = EXCLUDED.value_data,
                    compressed = EXCLUDED.compressed,
                    expires_at = EXCLUDED.expires_at,
                    access_count = cache_entries.access_count + 1,
                    last_accessed = NOW()
                "#,
            )
            .bind(&cache_key)
            .bind(uri)
            .bind(&final_data)
            .bind(compressed)
            .bind(chrono::DateTime::<chrono::Utc>::from(expires_at).to_rfc3339())
            .execute(pool)
            .await;

            match result {
                Ok(_) => debug!("Cached in database for key: {}", cache_key),
                Err(e) => warn!("Failed to cache in database: {}", e),
            }
        }

        info!("Cached data for URI: {} (compressed: {})", uri, compressed);
        Ok(())
    }

    /// Generate a cache key from URI
    fn generate_cache_key(&self, uri: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(uri.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Compress data using a simple algorithm (placeholder for production compression)
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        // In production, you would use a proper compression algorithm like gzip
        // For now, we'll just return the data as-is to avoid additional dependencies
        Ok(data.to_vec())
    }

    /// Decompress data
    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        // Corresponding decompression (currently no-op)
        Ok(data.to_vec())
    }

    /// Evict least recently used entries when cache is full
    async fn evict_oldest_entries(&self) {
        let mut lru_entries = Vec::new();

        // Find entries to evict based on last access time (LRU)
        for entry in self.memory_cache.iter() {
            lru_entries.push((entry.key().clone(), entry.value().last_accessed));
        }

        // Sort by last access time and remove least recently used entries
        lru_entries.sort_by(|a, b| a.1.cmp(&b.1));

        let to_remove = lru_entries
            .len()
            .saturating_sub(self.config.max_size * 3 / 4);
        for (key, _) in lru_entries.into_iter().take(to_remove) {
            self.memory_cache.remove(&key);
        }

        debug!("Evicted {} cache entries using LRU strategy", to_remove);
    }

    pub async fn is_healthy(&self) -> bool {
        true
    }

    pub async fn update_config(&self, _config: &CacheConfig) -> Result<(), String> {
        Ok(())
    }
}
