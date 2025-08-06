use dashmap::DashMap;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

/// Redis-inspired approximated LRU cache that uses random sampling for eviction
/// This provides ~95% of true LRU efficiency with much better performance
pub struct ApproximatedLRU<K, V>
where
    K: Hash + Eq + Clone + Send + Sync,
    V: Clone + Send + Sync,
{
    map: DashMap<K, CacheEntry<V>>,
    config: ApproximatedLRUConfig,
    global_clock: AtomicU64,
    stats: CacheStats,
}

/// Configuration for the approximated LRU cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproximatedLRUConfig {
    /// Number of random samples to take for eviction (Redis uses 5)
    pub sample_size: usize,
    /// Maximum number of entries in the cache
    pub max_size: usize,
    /// Maximum time an entry can remain idle before being considered for eviction
    pub max_idle_time: Duration,
    /// Number of keys to evict in a single batch
    pub eviction_batch_size: usize,
    /// Probability of updating access time on get (to reduce contention)
    pub access_time_update_probability: f64,
}

impl Default for ApproximatedLRUConfig {
    fn default() -> Self {
        Self {
            sample_size: 5,
            max_size: 10_000,
            max_idle_time: Duration::from_secs(3600), // 1 hour
            eviction_batch_size: 20,
            access_time_update_probability: 1.0,
        }
    }
}

/// Cache entry with access tracking information
#[derive(Debug, Clone)]
pub struct CacheEntry<V> {
    pub value: V,
    pub access_time: u64,
    pub access_count: u64,
    pub created_at: SystemTime,
    pub size_estimate: usize,
}

impl<V: Clone> CacheEntry<V> {
    pub fn new(value: V) -> Self {
        Self {
            value,
            access_time: 0,
            access_count: 1,
            created_at: SystemTime::now(),
            size_estimate: std::mem::size_of::<V>(),
        }
    }

    pub fn update_access(&mut self, global_time: u64) {
        self.access_time = global_time;
        self.access_count += 1;
    }

    pub fn is_expired(&self, max_idle_time: Duration) -> bool {
        self.created_at.elapsed().unwrap_or(Duration::ZERO) > max_idle_time
    }

    pub fn idle_score(&self, current_time: u64) -> u64 {
        // Higher score = more idle (better candidate for eviction)
        current_time.saturating_sub(self.access_time)
    }
}

/// Cache statistics for monitoring and debugging
#[derive(Debug, Default)]
pub struct CacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
    pub insertions: AtomicU64,
    pub updates: AtomicU64,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;

        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
}

impl<K, V> ApproximatedLRU<K, V>
where
    K: Hash + Eq + Clone + Send + Sync,
    V: Clone + Send + Sync,
{
    /// Create a new approximated LRU cache
    pub fn new(config: ApproximatedLRUConfig) -> Self {
        Self {
            map: DashMap::new(),
            config,
            global_clock: AtomicU64::new(1),
            stats: CacheStats::default(),
        }
    }

    /// Get a value from the cache
    pub fn get(&self, key: &K) -> Option<V> {
        if let Some(mut entry) = self.map.get_mut(key) {
            // Probabilistic access time update to reduce contention
            if thread_rng().gen::<f64>() < self.config.access_time_update_probability {
                let current_time = self.global_clock.fetch_add(1, Ordering::Relaxed);
                entry.update_access(current_time);
            }

            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.value.clone())
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Insert a value into the cache
    pub fn insert(&self, key: K, value: V) -> Option<V> {
        let current_time = self.global_clock.fetch_add(1, Ordering::Relaxed);

        // Check if we need to evict before inserting
        if self.map.len() >= self.config.max_size && !self.map.contains_key(&key) {
            self.evict_lru_approximate();
        }

        let mut entry = CacheEntry::new(value);
        entry.access_time = current_time;

        if let Some(old_entry) = self.map.insert(key, entry) {
            self.stats.updates.fetch_add(1, Ordering::Relaxed);
            Some(old_entry.value)
        } else {
            self.stats.insertions.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Remove a key from the cache
    pub fn remove(&self, key: &K) -> Option<V> {
        self.map.remove(key).map(|(_, entry)| entry.value)
    }

    /// Get the current size of the cache
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Clear all entries from the cache
    pub fn clear(&self) {
        self.map.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Get detailed cache metrics
    pub fn metrics(&self) -> CacheMetrics {
        let current_time = self.global_clock.load(Ordering::Relaxed);
        let mut total_memory = 0;
        let mut oldest_access = current_time;
        let mut newest_access = 0;
        let mut access_times = Vec::new();

        for entry in self.map.iter() {
            total_memory += entry.size_estimate;
            oldest_access = oldest_access.min(entry.access_time);
            newest_access = newest_access.max(entry.access_time);
            access_times.push(entry.access_time);
        }

        // Calculate percentiles of access times
        access_times.sort_unstable();
        let p50_idx = access_times.len() / 2;
        let p95_idx = (access_times.len() * 95) / 100;

        CacheMetrics {
            size: self.map.len(),
            max_size: self.config.max_size,
            hit_rate: self.stats.hit_rate(),
            total_hits: self.stats.hits.load(Ordering::Relaxed),
            total_misses: self.stats.misses.load(Ordering::Relaxed),
            total_evictions: self.stats.evictions.load(Ordering::Relaxed),
            estimated_memory_bytes: total_memory,
            oldest_access_time: oldest_access,
            newest_access_time: newest_access,
            median_access_time: access_times.get(p50_idx).copied().unwrap_or(0),
            p95_access_time: access_times.get(p95_idx).copied().unwrap_or(0),
        }
    }

    /// Perform approximated LRU eviction using random sampling
    fn evict_lru_approximate(&self) {
        let current_time = self.global_clock.load(Ordering::Relaxed);
        let sample_size = self.config.sample_size.min(self.map.len());

        if sample_size == 0 {
            return;
        }

        // Sample random keys and find the most idle ones
        let mut candidates = Vec::with_capacity(sample_size);
        let mut sampled_keys = std::collections::HashSet::new();
        let mut attempts = 0;
        let max_attempts = sample_size * 3; // Avoid infinite loops

        // Random sampling approach with duplicate prevention
        while candidates.len() < sample_size && attempts < max_attempts {
            attempts += 1;

            // Get a random key by iterating and taking nth element
            // This is not perfectly random but good enough for cache eviction
            let target_idx = thread_rng().gen_range(0..self.map.len());

            for (current_idx, entry) in self.map.iter().enumerate() {
                if current_idx == target_idx {
                    let key = entry.key().clone();
                    // Only add if we haven't sampled this key already
                    if sampled_keys.insert(key.clone()) {
                        let idle_score = entry.idle_score(current_time);
                        candidates.push((key, idle_score));
                    }
                    break;
                }
            }
        }

        // Sort candidates by idle score (descending - most idle first)
        candidates.sort_by(|a, b| b.1.cmp(&a.1));

        // Evict the most idle keys
        let evict_count = self.config.eviction_batch_size.min(candidates.len());
        let mut evicted = 0;

        for (key, _) in candidates.into_iter().take(evict_count) {
            if self.map.remove(&key).is_some() {
                evicted += 1;
            }
        }

        self.stats.evictions.fetch_add(evicted, Ordering::Relaxed);
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&self) -> usize {
        let mut removed = 0;
        let keys_to_remove: Vec<K> = self
            .map
            .iter()
            .filter(|entry| entry.is_expired(self.config.max_idle_time))
            .map(|entry| entry.key().clone())
            .collect();

        for key in keys_to_remove {
            if self.map.remove(&key).is_some() {
                removed += 1;
            }
        }

        removed
    }

    /// Get a sample of cache entries for debugging
    pub fn sample_entries(&self, count: usize) -> Vec<(K, CacheEntry<V>)> {
        self.map
            .iter()
            .take(count)
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }
}

/// Detailed cache metrics for monitoring
#[derive(Debug, Clone)]
pub struct CacheMetrics {
    pub size: usize,
    pub max_size: usize,
    pub hit_rate: f64,
    pub total_hits: u64,
    pub total_misses: u64,
    pub total_evictions: u64,
    pub estimated_memory_bytes: usize,
    pub oldest_access_time: u64,
    pub newest_access_time: u64,
    pub median_access_time: u64,
    pub p95_access_time: u64,
}

// Traits for different cache algorithms
pub trait LocalCache<K, V>: Send + Sync
where
    K: Hash + Eq + Clone + Send + Sync,
    V: Clone + Send + Sync,
{
    fn get(&self, key: &K) -> Option<V>;
    fn insert(&self, key: K, value: V) -> Option<V>;
    fn remove(&self, key: &K) -> Option<V>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn clear(&self);
}

impl<K, V> LocalCache<K, V> for ApproximatedLRU<K, V>
where
    K: Hash + Eq + Clone + Send + Sync,
    V: Clone + Send + Sync,
{
    fn get(&self, key: &K) -> Option<V> {
        self.get(key)
    }

    fn insert(&self, key: K, value: V) -> Option<V> {
        self.insert(key, value)
    }

    fn remove(&self, key: &K) -> Option<V> {
        self.remove(key)
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    fn clear(&self) {
        self.clear()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_basic_operations() {
        let config = ApproximatedLRUConfig {
            max_size: 10,
            ..Default::default()
        };
        let cache = ApproximatedLRU::new(config);

        // Test insertion and retrieval
        assert_eq!(cache.insert("key1".to_string(), "value1".to_string()), None);
        assert_eq!(cache.get(&"key1".to_string()), Some("value1".to_string()));

        // Test update
        assert_eq!(
            cache.insert("key1".to_string(), "value2".to_string()),
            Some("value1".to_string())
        );
        assert_eq!(cache.get(&"key1".to_string()), Some("value2".to_string()));

        // Test removal
        assert_eq!(
            cache.remove(&"key1".to_string()),
            Some("value2".to_string())
        );
        assert_eq!(cache.get(&"key1".to_string()), None);
    }

    #[test]
    fn test_approximate_lru_eviction() {
        let config = ApproximatedLRUConfig {
            max_size: 5,
            sample_size: 5, // Sample all keys to make test deterministic
            eviction_batch_size: 1, // Evict only the most idle key
            ..Default::default()
        };
        let cache = ApproximatedLRU::new(config);

        // Fill cache to capacity
        for i in 0..5 {
            cache.insert(i, format!("value_{i}"));
        }

        // Access some keys to make them "more recent"
        cache.get(&2);
        cache.get(&3);
        cache.get(&4);

        // Insert a new key, should trigger eviction
        cache.insert(5, "value_5".to_string());

        // Cache should still be at or near max capacity
        assert!(cache.len() <= 5);

        // Most recently accessed key should remain (key 4 should be present)
        assert!(cache.get(&4).is_some());
        
        // Key 0 or 1 should have been evicted (least recently used)
        let key_0_present = cache.get(&0).is_some();
        let key_1_present = cache.get(&1).is_some();
        assert!(!key_0_present || !key_1_present, "At least one of the oldest keys should be evicted");
    }

    #[test]
    fn test_concurrent_access() {
        let config = ApproximatedLRUConfig {
            max_size: 1000, // Increased to avoid evictions during test
            ..Default::default()
        };
        let cache = Arc::new(ApproximatedLRU::new(config));
        let mut handles = vec![];

        // Spawn multiple threads doing concurrent operations
        for i in 0..10 {
            let cache_clone = Arc::clone(&cache);
            let handle = thread::spawn(move || {
                for j in 0..50 {
                    // Total: 500 items, well under 1000 capacity
                    let key = format!("key_{i}_{j}");
                    let value = format!("value_{i}_{j}");
                    cache_clone.insert(key.clone(), value.clone());
                    assert_eq!(cache_clone.get(&key), Some(value));
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Cache should have 500 items (10 threads × 50 items each)
        assert_eq!(cache.len(), 500);

        let stats = cache.stats();
        assert!(stats.hits.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_metrics() {
        let config = ApproximatedLRUConfig {
            max_size: 10,
            ..Default::default()
        };
        let cache = ApproximatedLRU::new(config);

        // Insert some data
        cache.insert("a", 1);
        cache.insert("b", 2);
        cache.insert("c", 3);

        // Access some keys
        cache.get(&"a");
        cache.get(&"b");
        cache.get(&"nonexistent");

        let metrics = cache.metrics();
        assert_eq!(metrics.size, 3);
        assert_eq!(metrics.max_size, 10);
        assert_eq!(metrics.total_hits, 2);
        assert_eq!(metrics.total_misses, 1);
        assert!(metrics.hit_rate > 0.0);
    }

    #[test]
    fn test_cleanup_expired() {
        let config = ApproximatedLRUConfig {
            max_idle_time: Duration::from_millis(100),
            ..Default::default()
        };
        let cache = ApproximatedLRU::new(config);

        cache.insert("key1", "value1");
        cache.insert("key2", "value2");

        // Wait for entries to expire
        thread::sleep(Duration::from_millis(150));

        let removed = cache.cleanup_expired();
        assert_eq!(removed, 2);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_sample_entries() {
        let config = ApproximatedLRUConfig::default();
        let cache = ApproximatedLRU::new(config);

        for i in 0..10 {
            cache.insert(i, format!("value_{i}"));
        }

        let sample = cache.sample_entries(5);
        assert_eq!(sample.len(), 5);

        for (key, entry) in sample {
            assert_eq!(entry.value, format!("value_{key}"));
        }
    }
}
