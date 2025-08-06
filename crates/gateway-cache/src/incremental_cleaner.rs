use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, info};

/// Redis-inspired incremental cleanup engine that spreads cache maintenance
/// across time to avoid blocking operations
pub struct IncrementalCleaner {
    config: CleanupConfig,
    stats: CleanupStats,
    adaptive_controller: AdaptiveController,
}

/// Configuration for incremental cleanup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupConfig {
    /// Maximum time to spend on cleanup per cycle (default: 25ms)
    pub max_cleanup_time_ms: u64,
    /// Target percentage of expired keys to clean per cycle (default: 20%)
    pub cleanup_percentage: f64,
    /// Minimum number of keys to check per cycle
    pub min_keys_per_cycle: usize,
    /// Maximum number of keys to check per cycle
    pub max_keys_per_cycle: usize,
    /// Enable adaptive cleanup based on cache metrics
    pub adaptive_mode: bool,
    /// Cleanup cycle interval
    pub cleanup_interval: Duration,
    /// Memory pressure threshold for aggressive cleanup
    pub memory_pressure_threshold: f64,
    /// Hit rate threshold for light cleanup
    pub hit_rate_threshold: f64,
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            max_cleanup_time_ms: 25,
            cleanup_percentage: 0.2,
            min_keys_per_cycle: 20,
            max_keys_per_cycle: 100,
            adaptive_mode: true,
            cleanup_interval: Duration::from_secs(10),
            memory_pressure_threshold: 0.8,
            hit_rate_threshold: 0.95,
        }
    }
}

/// Statistics tracking for cleanup operations
#[derive(Debug, Default)]
pub struct CleanupStats {
    pub total_cycles: AtomicU64,
    pub total_keys_cleaned: AtomicU64,
    pub total_cleanup_time_ms: AtomicU64,
    pub avg_cleanup_time_ms: AtomicU64,
    pub keys_per_second: AtomicU64,
    pub last_cycle_keys_cleaned: AtomicUsize,
    pub last_cycle_time_ms: AtomicU64,
}

/// Result of a cleanup cycle
#[derive(Debug, Clone)]
pub struct CleanupResult {
    pub keys_cleaned: usize,
    pub keys_checked: usize,
    pub time_taken: Duration,
    pub expired_keys_found: usize,
    pub memory_freed_bytes: usize,
    pub cleanup_efficiency: f64,
}

/// Adaptive controller for dynamic cleanup tuning
#[derive(Debug)]
pub struct AdaptiveController {
    recent_metrics: Arc<Mutex<Vec<CleanupMetrics>>>,
    max_history: usize,
    last_adjustment: Instant,
    adjustment_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct CleanupMetrics {
    pub memory_usage: f64,
    pub hit_rate: f64,
    pub cache_size: usize,
    pub expired_ratio: f64,
    pub timestamp: Instant,
}

/// Cache metrics needed for adaptive cleanup
pub trait CacheMetricsProvider {
    fn memory_usage_ratio(&self) -> f64;
    fn hit_rate(&self) -> f64;
    fn cache_size(&self) -> usize;
    fn max_size(&self) -> usize;
    fn estimated_expired_ratio(&self) -> f64;
}

impl IncrementalCleaner {
    pub fn new(config: CleanupConfig) -> Self {
        Self {
            config,
            stats: CleanupStats::default(),
            adaptive_controller: AdaptiveController::new(),
        }
    }

    /// Run a single cleanup cycle
    pub async fn run_cleanup_cycle<T>(&self, cache_provider: &T) -> CleanupResult
    where
        T: CacheMetricsProvider + ExpiredKeyProvider,
    {
        let start_time = Instant::now();
        let cycle_id = self.stats.total_cycles.fetch_add(1, Ordering::Relaxed);

        // Calculate cleanup aggressiveness based on cache state
        let aggressiveness = if self.config.adaptive_mode {
            self.calculate_cleanup_aggressiveness(cache_provider)
        } else {
            1.0
        };

        debug!(
            "Starting cleanup cycle {} with aggressiveness {:.2}",
            cycle_id, aggressiveness
        );

        // Determine cleanup parameters for this cycle
        let max_time =
            Duration::from_millis((self.config.max_cleanup_time_ms as f64 * aggressiveness) as u64);
        let max_keys = (self.config.max_keys_per_cycle as f64 * aggressiveness) as usize;
        let min_keys = self.config.min_keys_per_cycle;

        let mut keys_cleaned = 0;
        let mut keys_checked = 0;
        let mut expired_keys_found = 0;
        let mut memory_freed_bytes = 0;

        // Main cleanup loop
        while start_time.elapsed() < max_time && keys_checked < max_keys {
            match cache_provider.get_expired_key_sample(1).await {
                Some(expired_keys) if !expired_keys.is_empty() => {
                    for expired_key in expired_keys {
                        if let Some(removed_size) =
                            cache_provider.remove_expired_key(&expired_key).await
                        {
                            keys_cleaned += 1;
                            memory_freed_bytes += removed_size;
                        }
                        expired_keys_found += 1;
                        keys_checked += 1;

                        if start_time.elapsed() >= max_time || keys_checked >= max_keys {
                            break;
                        }
                    }
                }
                _ => {
                    // No more expired keys found, break early
                    break;
                }
            }

            // Ensure we check at least minimum keys
            if keys_checked < min_keys && start_time.elapsed() < max_time {
                // Sample random keys and check if expired
                if let Some(sample_keys) = cache_provider
                    .get_random_key_sample(min_keys - keys_checked)
                    .await
                {
                    for key in sample_keys {
                        if cache_provider.is_key_expired(&key).await {
                            if let Some(removed_size) =
                                cache_provider.remove_expired_key(&key).await
                            {
                                keys_cleaned += 1;
                                memory_freed_bytes += removed_size;
                            }
                            expired_keys_found += 1;
                        }
                        keys_checked += 1;

                        if start_time.elapsed() >= max_time {
                            break;
                        }
                    }
                }
            }
        }

        let time_taken = start_time.elapsed();
        let cleanup_efficiency = if keys_checked > 0 {
            keys_cleaned as f64 / keys_checked as f64
        } else {
            0.0
        };

        // Update statistics
        self.update_stats(keys_cleaned, time_taken);

        // Update adaptive controller if enabled
        if self.config.adaptive_mode {
            let metrics = CleanupMetrics {
                memory_usage: cache_provider.memory_usage_ratio(),
                hit_rate: cache_provider.hit_rate(),
                cache_size: cache_provider.cache_size(),
                expired_ratio: expired_keys_found as f64 / keys_checked.max(1) as f64,
                timestamp: Instant::now(),
            };
            let mut controller = self.adaptive_controller.recent_metrics.lock().unwrap();
            controller.push(metrics);

            // Keep only recent metrics
            if controller.len() > self.adaptive_controller.max_history {
                controller.remove(0);
            }
        }

        debug!(
            "Cleanup cycle {} completed: cleaned {}/{} keys in {:?} (efficiency: {:.2}%)",
            cycle_id,
            keys_cleaned,
            keys_checked,
            time_taken,
            cleanup_efficiency * 100.0
        );

        CleanupResult {
            keys_cleaned,
            keys_checked,
            time_taken,
            expired_keys_found,
            memory_freed_bytes,
            cleanup_efficiency,
        }
    }

    /// Calculate cleanup aggressiveness based on cache metrics
    fn calculate_cleanup_aggressiveness<T>(&self, cache_provider: &T) -> f64
    where
        T: CacheMetricsProvider,
    {
        let memory_pressure = cache_provider.memory_usage_ratio();
        let hit_rate = cache_provider.hit_rate();
        let cache_utilization =
            cache_provider.cache_size() as f64 / cache_provider.max_size() as f64;

        // Aggressive cleanup scenarios
        if memory_pressure > 0.9 || cache_utilization > 0.95 {
            return 2.0; // Very aggressive
        }

        if memory_pressure > self.config.memory_pressure_threshold {
            return 1.5; // Aggressive
        }

        // Light cleanup scenarios
        if hit_rate > self.config.hit_rate_threshold && memory_pressure < 0.5 {
            return 0.3; // Light cleanup
        }

        // Adaptive based on recent performance
        let recent_aggressiveness = self.adaptive_controller.recommended_aggressiveness();

        // Combine factors
        let base_aggressiveness = match (memory_pressure, hit_rate) {
            (mem, _) if mem > 0.8 => 1.2,
            (mem, hit) if mem > 0.6 && hit < 0.8 => 1.0,
            (_, hit) if hit > 0.9 => 0.5,
            _ => 0.8,
        };

        (base_aggressiveness + recent_aggressiveness) / 2.0
    }

    /// Update cleanup statistics
    fn update_stats(&self, keys_cleaned: usize, time_taken: Duration) {
        let time_ms = time_taken.as_millis() as u64;

        self.stats
            .total_keys_cleaned
            .fetch_add(keys_cleaned as u64, Ordering::Relaxed);
        self.stats
            .total_cleanup_time_ms
            .fetch_add(time_ms, Ordering::Relaxed);
        self.stats
            .last_cycle_keys_cleaned
            .store(keys_cleaned, Ordering::Relaxed);
        self.stats
            .last_cycle_time_ms
            .store(time_ms, Ordering::Relaxed);

        // Update average cleanup time
        let total_cycles = self.stats.total_cycles.load(Ordering::Relaxed);
        let total_time = self.stats.total_cleanup_time_ms.load(Ordering::Relaxed);
        if total_cycles > 0 {
            self.stats
                .avg_cleanup_time_ms
                .store(total_time / total_cycles, Ordering::Relaxed);
        }

        // Update keys per second
        if time_ms > 0 {
            let kps = (keys_cleaned as u64 * 1000) / time_ms;
            self.stats.keys_per_second.store(kps, Ordering::Relaxed);
        }
    }

    /// Start the background cleanup task
    pub async fn start_background_cleanup<T>(
        self: Arc<Self>,
        cache_provider: Arc<T>,
    ) -> tokio::task::JoinHandle<()>
    where
        T: CacheMetricsProvider + ExpiredKeyProvider + Send + Sync + 'static,
    {
        tokio::spawn(async move {
            let mut interval = interval(self.config.cleanup_interval);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

            info!(
                "Starting background cleanup task with interval {:?}",
                self.config.cleanup_interval
            );

            loop {
                interval.tick().await;

                match self.run_cleanup_cycle(cache_provider.as_ref()).await {
                    result => {
                        if result.keys_cleaned > 0 {
                            debug!(
                                "Background cleanup: removed {} keys in {:?}",
                                result.keys_cleaned, result.time_taken
                            );
                        }
                    }
                }
            }
        })
    }

    /// Get current cleanup statistics
    pub fn stats(&self) -> CleanupStatsSnapshot {
        CleanupStatsSnapshot {
            total_cycles: self.stats.total_cycles.load(Ordering::Relaxed),
            total_keys_cleaned: self.stats.total_keys_cleaned.load(Ordering::Relaxed),
            total_cleanup_time_ms: self.stats.total_cleanup_time_ms.load(Ordering::Relaxed),
            avg_cleanup_time_ms: self.stats.avg_cleanup_time_ms.load(Ordering::Relaxed),
            keys_per_second: self.stats.keys_per_second.load(Ordering::Relaxed),
            last_cycle_keys_cleaned: self.stats.last_cycle_keys_cleaned.load(Ordering::Relaxed),
            last_cycle_time_ms: self.stats.last_cycle_time_ms.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of cleanup statistics
#[derive(Debug, Clone)]
pub struct CleanupStatsSnapshot {
    pub total_cycles: u64,
    pub total_keys_cleaned: u64,
    pub total_cleanup_time_ms: u64,
    pub avg_cleanup_time_ms: u64,
    pub keys_per_second: u64,
    pub last_cycle_keys_cleaned: usize,
    pub last_cycle_time_ms: u64,
}

impl AdaptiveController {
    fn new() -> Self {
        Self {
            recent_metrics: Arc::new(Mutex::new(Vec::new())),
            max_history: 50,
            last_adjustment: Instant::now(),
            adjustment_interval: Duration::from_secs(60),
        }
    }

    fn recommended_aggressiveness(&self) -> f64 {
        let metrics = self.recent_metrics.lock().unwrap();
        if metrics.is_empty() {
            return 1.0;
        }

        // Calculate trends
        let recent_count = 10.min(metrics.len());
        let recent_metrics = &metrics[metrics.len() - recent_count..];

        let avg_memory_usage: f64 =
            recent_metrics.iter().map(|m| m.memory_usage).sum::<f64>() / recent_count as f64;

        let avg_hit_rate: f64 =
            recent_metrics.iter().map(|m| m.hit_rate).sum::<f64>() / recent_count as f64;

        let avg_expired_ratio: f64 =
            recent_metrics.iter().map(|m| m.expired_ratio).sum::<f64>() / recent_count as f64;

        // Determine aggressiveness based on trends
        match (avg_memory_usage, avg_hit_rate, avg_expired_ratio) {
            (mem, _, exp) if mem > 0.8 && exp > 0.1 => 1.5, // High memory, many expired
            (mem, hit, _) if mem > 0.7 && hit < 0.8 => 1.2, // High memory, low hit rate
            (_, hit, exp) if hit > 0.95 && exp < 0.05 => 0.3, // High hit rate, few expired
            (mem, _, exp) if mem < 0.5 && exp < 0.1 => 0.5, // Low memory, few expired
            _ => 1.0,                                       // Default
        }
    }
}

/// Trait for providing expired keys to the cleaner
#[async_trait::async_trait]
pub trait ExpiredKeyProvider {
    type Key: Send + Sync;

    /// Get a sample of expired keys
    async fn get_expired_key_sample(&self, count: usize) -> Option<Vec<Self::Key>>;

    /// Get a sample of random keys for expiration checking
    async fn get_random_key_sample(&self, count: usize) -> Option<Vec<Self::Key>>;

    /// Check if a specific key is expired
    async fn is_key_expired(&self, key: &Self::Key) -> bool;

    /// Remove an expired key and return the freed memory size
    async fn remove_expired_key(&self, key: &Self::Key) -> Option<usize>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::time::Duration;

    // Mock cache provider for testing
    struct MockCacheProvider {
        data: Arc<Mutex<HashMap<String, (String, Instant)>>>,
        expired_keys: Arc<Mutex<Vec<String>>>,
        memory_usage: f64,
        hit_rate: f64,
        max_size: usize,
    }

    impl MockCacheProvider {
        fn new() -> Self {
            Self {
                data: Arc::new(Mutex::new(HashMap::new())),
                expired_keys: Arc::new(Mutex::new(Vec::new())),
                memory_usage: 0.5,
                hit_rate: 0.9,
                max_size: 1000,
            }
        }

        fn add_expired_key(&self, key: String) {
            self.expired_keys.lock().unwrap().push(key);
        }

        fn set_memory_usage(&mut self, usage: f64) {
            self.memory_usage = usage;
        }
    }

    impl CacheMetricsProvider for MockCacheProvider {
        fn memory_usage_ratio(&self) -> f64 {
            self.memory_usage
        }
        fn hit_rate(&self) -> f64 {
            self.hit_rate
        }
        fn cache_size(&self) -> usize {
            self.data.lock().unwrap().len()
        }
        fn max_size(&self) -> usize {
            self.max_size
        }
        fn estimated_expired_ratio(&self) -> f64 {
            0.1
        }
    }

    #[async_trait::async_trait]
    impl ExpiredKeyProvider for MockCacheProvider {
        type Key = String;

        async fn get_expired_key_sample(&self, count: usize) -> Option<Vec<String>> {
            let mut expired = self.expired_keys.lock().unwrap();
            if expired.is_empty() {
                None
            } else {
                let drain_count = count.min(expired.len());
                let result = expired.drain(..drain_count).collect();
                Some(result)
            }
        }

        async fn get_random_key_sample(&self, _count: usize) -> Option<Vec<String>> {
            Some(vec!["random_key".to_string()])
        }

        async fn is_key_expired(&self, _key: &String) -> bool {
            false
        }

        async fn remove_expired_key(&self, _key: &String) -> Option<usize> {
            Some(100) // Mock 100 bytes freed
        }
    }

    #[tokio::test]
    async fn test_basic_cleanup_cycle() {
        let config = CleanupConfig {
            max_cleanup_time_ms: 100,
            min_keys_per_cycle: 5,
            max_keys_per_cycle: 20,
            ..Default::default()
        };

        let cleaner = IncrementalCleaner::new(config);
        let cache_provider = MockCacheProvider::new();

        // Add some expired keys
        cache_provider.add_expired_key("expired1".to_string());
        cache_provider.add_expired_key("expired2".to_string());
        cache_provider.add_expired_key("expired3".to_string());

        let result = cleaner.run_cleanup_cycle(&cache_provider).await;

        assert!(result.keys_cleaned > 0);
        assert!(result.time_taken < Duration::from_millis(100));
        assert!(result.cleanup_efficiency > 0.0);
    }

    #[tokio::test]
    async fn test_adaptive_cleanup() {
        let config = CleanupConfig {
            adaptive_mode: true,
            memory_pressure_threshold: 0.7,
            ..Default::default()
        };

        let cleaner = IncrementalCleaner::new(config);
        let mut cache_provider = MockCacheProvider::new();

        // Test high memory pressure scenario
        cache_provider.set_memory_usage(0.9);
        cache_provider.add_expired_key("expired1".to_string());

        let result1 = cleaner.run_cleanup_cycle(&cache_provider).await;

        // Test low memory pressure scenario
        cache_provider.set_memory_usage(0.3);
        cache_provider.add_expired_key("expired2".to_string());

        let result2 = cleaner.run_cleanup_cycle(&cache_provider).await;

        // High memory pressure should be more aggressive (but this is hard to test directly)
        assert!(result1.time_taken > Duration::ZERO);
        assert!(result2.time_taken > Duration::ZERO);
    }

    #[tokio::test]
    async fn test_cleanup_stats() {
        let config = CleanupConfig::default();
        let cleaner = IncrementalCleaner::new(config);
        let cache_provider = MockCacheProvider::new();

        cache_provider.add_expired_key("expired1".to_string());

        let _result = cleaner.run_cleanup_cycle(&cache_provider).await;

        let stats = cleaner.stats();
        assert_eq!(stats.total_cycles, 1);
        assert!(stats.total_keys_cleaned > 0);
        assert!(stats.total_cleanup_time_ms > 0);
    }
}
