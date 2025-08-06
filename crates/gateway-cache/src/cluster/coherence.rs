use dashmap::DashSet;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, error, info, warn};

use super::{CacheOp, ClusterMessage, ClusterPayload, MessageType, UDPMulticastCluster};

/// Cache coherence manager for maintaining consistency across cluster nodes
pub struct CacheCoherenceManager {
    cluster: Arc<UDPMulticastCluster>,
    config: CoherenceConfig,
    dirty_keys: Arc<DashSet<String>>,
    invalidation_log: Arc<RwLock<InvalidationLog>>,
    conflict_resolver: ConflictResolver,
    sync_task: Option<JoinHandle<()>>,
    stats: CoherenceStats,
}

/// Configuration for cache coherence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoherenceConfig {
    /// Coherence strategy to use
    pub strategy: CoherenceStrategy,
    /// Sync interval for write-behind strategy
    pub sync_interval: Duration,
    /// Conflict resolution strategy
    pub conflict_resolution: ConflictResolution,
    /// Maximum batch size for bulk operations
    pub max_batch_size: usize,
    /// Timeout for invalidation acknowledgments
    pub invalidation_timeout: Duration,
    /// Enable conflict detection
    pub conflict_detection: bool,
    /// Maximum time to keep invalidation log entries
    pub log_retention_time: Duration,
}

impl Default for CoherenceConfig {
    fn default() -> Self {
        Self {
            strategy: CoherenceStrategy::WriteBehind,
            sync_interval: Duration::from_secs(30),
            conflict_resolution: ConflictResolution::LastWriterWins,
            max_batch_size: 100,
            invalidation_timeout: Duration::from_secs(5),
            conflict_detection: true,
            log_retention_time: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Cache coherence strategies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CoherenceStrategy {
    /// Immediately invalidate on write
    WriteThrough,
    /// Periodic sync of dirty keys
    WriteBehind,
    /// Write directly to persistent store, skip cache
    WriteAround,
    /// No coherence (each node maintains independent cache)
    None,
}

/// Conflict resolution strategies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConflictResolution {
    /// Last write wins based on timestamp
    LastWriterWins,
    /// Use vector clocks for conflict detection
    VectorClock,
    /// Manual conflict resolution (return error)
    Manual,
    /// First writer wins
    FirstWriterWins,
}

/// Invalidation log entry
#[derive(Debug, Clone)]
pub struct InvalidationEntry {
    pub key: String,
    pub operation: CacheOp,
    pub timestamp: Instant,
    pub node_id: String,
    pub version: u64,
    pub acknowledged_by: HashSet<String>,
}

/// Invalidation log for tracking cache operations
#[derive(Debug, Default)]
pub struct InvalidationLog {
    entries: HashMap<String, InvalidationEntry>,
    sequence: u64,
}

/// Conflict resolver for handling cache conflicts
pub struct ConflictResolver {
    config: CoherenceConfig,
    vector_clocks: Arc<RwLock<HashMap<String, VectorClock>>>,
}

/// Vector clock for conflict detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorClock {
    clocks: HashMap<String, u64>,
}

/// Cache coherence statistics
#[derive(Debug, Default)]
pub struct CoherenceStats {
    pub invalidations_sent: std::sync::atomic::AtomicU64,
    pub invalidations_received: std::sync::atomic::AtomicU64,
    pub conflicts_detected: std::sync::atomic::AtomicU64,
    pub conflicts_resolved: std::sync::atomic::AtomicU64,
    pub sync_operations: std::sync::atomic::AtomicU64,
    pub failed_invalidations: std::sync::atomic::AtomicU64,
}

impl CacheCoherenceManager {
    /// Create a new cache coherence manager
    pub fn new(cluster: Arc<UDPMulticastCluster>, config: CoherenceConfig) -> Self {
        let conflict_resolver = ConflictResolver::new(config.clone());

        Self {
            cluster,
            config,
            dirty_keys: Arc::new(DashSet::new()),
            invalidation_log: Arc::new(RwLock::new(InvalidationLog::default())),
            conflict_resolver,
            sync_task: None,
            stats: CoherenceStats::default(),
        }
    }

    /// Start the coherence manager
    pub async fn start(&mut self) -> Result<(), CoherenceError> {
        if self.config.strategy == CoherenceStrategy::WriteBehind {
            self.start_sync_task().await;
        }

        info!(
            "Cache coherence manager started with strategy: {:?}",
            self.config.strategy
        );
        Ok(())
    }

    /// Stop the coherence manager
    pub async fn stop(&mut self) {
        if let Some(task) = self.sync_task.take() {
            task.abort();
        }

        info!("Cache coherence manager stopped");
    }

    /// Handle a cache write operation
    pub async fn handle_cache_write(
        &self,
        key: String,
        _value: Vec<u8>,
    ) -> Result<(), CoherenceError> {
        match self.config.strategy {
            CoherenceStrategy::WriteThrough => {
                self.invalidate_cluster_key(&key).await?;
            }
            CoherenceStrategy::WriteBehind => {
                self.dirty_keys.insert(key);
            }
            CoherenceStrategy::WriteAround => {
                // Write directly to persistent store, skip cache coherence
            }
            CoherenceStrategy::None => {
                // No coherence needed
            }
        }

        Ok(())
    }

    /// Handle a cache invalidate operation
    pub async fn handle_cache_invalidate(&self, key: String) -> Result<(), CoherenceError> {
        if self.config.strategy != CoherenceStrategy::None {
            self.invalidate_cluster_key(&key).await?;
        }

        Ok(())
    }

    /// Handle received invalidation message
    pub async fn handle_invalidation_message(
        &self,
        message: ClusterMessage,
    ) -> Result<(), CoherenceError> {
        if let ClusterPayload::CacheOperation {
            ref key,
            ref operation,
            ref data,
        } = message.payload
        {
            match operation {
                CacheOp::Invalidate => {
                    debug!("Processing cache invalidation for key: {}", key);
                    self.stats
                        .invalidations_received
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // Apply invalidation locally
                    self.apply_local_invalidation(&key).await?;

                    // Acknowledge invalidation
                    self.acknowledge_invalidation(
                        message.message_id.clone(),
                        message.sender_id.clone(),
                    )
                    .await?;
                }
                CacheOp::Update => {
                    debug!("Processing cache update for key: {}", key);

                    // Check for conflicts
                    if self.config.conflict_detection {
                        if let Some(conflict) = self.detect_conflict(&key, &message).await? {
                            warn!("Conflict detected for key {}: {:?}", key, conflict);
                            self.stats
                                .conflicts_detected
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            // Resolve conflict
                            self.resolve_conflict(conflict).await?;
                            self.stats
                                .conflicts_resolved
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }

                    // Apply update locally
                    if let Some(data) = data {
                        self.apply_local_update(&key, data.clone()).await?;
                    }
                }
                CacheOp::Delete => {
                    debug!("Processing cache delete for key: {}", key);
                    self.apply_local_delete(&key).await?;
                }
                CacheOp::Sync => {
                    debug!("Processing cache sync for key: {}", key);
                    // Sync from persistent store if needed
                    self.sync_from_persistent_store(&key).await?;
                }
            }

            // Update invalidation log
            self.update_invalidation_log(key.clone(), *operation, message)
                .await;
        }

        Ok(())
    }

    /// Invalidate a key across the cluster
    async fn invalidate_cluster_key(&self, key: &str) -> Result<(), CoherenceError> {
        let invalidation_message = ClusterMessage {
            message_id: uuid::Uuid::new_v4().to_string(),
            message_type: MessageType::CacheInvalidate,
            sender_id: self.cluster.node_id.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            sequence: 0, // Will be set by cluster
            payload: ClusterPayload::CacheOperation {
                key: key.to_string(),
                operation: CacheOp::Invalidate,
                data: None,
            },
            checksum: String::new(),
        };

        self.cluster
            .send_multicast_message(invalidation_message)
            .await
            .map_err(CoherenceError::Network)?;

        self.stats
            .invalidations_sent
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Ok(())
    }

    /// Start the periodic sync task for write-behind strategy
    async fn start_sync_task(&mut self) {
        let dirty_keys = Arc::clone(&self.dirty_keys);
        let cluster = Arc::clone(&self.cluster);
        let sync_interval = self.config.sync_interval;
        let max_batch_size = self.config.max_batch_size;

        let task = tokio::spawn(async move {
            let mut interval = interval(sync_interval);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                // Collect dirty keys
                let keys_to_sync: Vec<String> = dirty_keys
                    .iter()
                    .take(max_batch_size)
                    .map(|entry| entry.key().clone())
                    .collect();

                if keys_to_sync.is_empty() {
                    continue;
                }

                debug!("Syncing {} dirty keys", keys_to_sync.len());

                // Send sync messages for each key
                for key in &keys_to_sync {
                    let sync_message = ClusterMessage {
                        message_id: uuid::Uuid::new_v4().to_string(),
                        message_type: MessageType::CacheUpdate,
                        sender_id: cluster.node_id.clone(),
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        sequence: 0,
                        payload: ClusterPayload::CacheOperation {
                            key: key.clone(),
                            operation: CacheOp::Sync,
                            data: None,
                        },
                        checksum: String::new(),
                    };

                    if let Err(e) = cluster.send_multicast_message(sync_message).await {
                        warn!("Failed to send sync message for key {}: {}", key, e);
                    }
                }

                // Remove synced keys from dirty set
                for key in keys_to_sync {
                    dirty_keys.remove(&key);
                }
            }
        });

        self.sync_task = Some(task);
    }

    /// Apply local cache invalidation
    async fn apply_local_invalidation(&self, key: &str) -> Result<(), CoherenceError> {
        // This would be implemented by the actual cache
        debug!("Applying local invalidation for key: {}", key);
        Ok(())
    }

    /// Apply local cache update
    async fn apply_local_update(&self, key: &str, data: Vec<u8>) -> Result<(), CoherenceError> {
        // This would be implemented by the actual cache
        debug!(
            "Applying local update for key: {} ({} bytes)",
            key,
            data.len()
        );
        Ok(())
    }

    /// Apply local cache delete
    async fn apply_local_delete(&self, key: &str) -> Result<(), CoherenceError> {
        // This would be implemented by the actual cache
        debug!("Applying local delete for key: {}", key);
        Ok(())
    }

    /// Sync from persistent store
    async fn sync_from_persistent_store(&self, key: &str) -> Result<(), CoherenceError> {
        // This would be implemented by the actual cache/storage layer
        debug!("Syncing key from persistent store: {}", key);
        Ok(())
    }

    /// Acknowledge invalidation
    async fn acknowledge_invalidation(
        &self,
        message_id: String,
        sender_id: String,
    ) -> Result<(), CoherenceError> {
        // Send acknowledgment back to sender
        debug!(
            "Acknowledging invalidation {} from {}",
            message_id, sender_id
        );
        Ok(())
    }

    /// Detect conflicts for a cache operation
    async fn detect_conflict(
        &self,
        key: &str,
        message: &ClusterMessage,
    ) -> Result<Option<CacheConflict>, CoherenceError> {
        let log = self.invalidation_log.read().await;

        if let Some(existing_entry) = log.entries.get(key) {
            // Check if there's a timing conflict
            let message_time = std::time::UNIX_EPOCH + Duration::from_secs(message.timestamp);
            let existing_time = std::time::UNIX_EPOCH + existing_entry.timestamp.elapsed();

            if message_time < existing_time && message.sender_id != existing_entry.node_id {
                return Ok(Some(CacheConflict {
                    key: key.to_string(),
                    conflicting_operations: vec![
                        ConflictingOperation {
                            node_id: existing_entry.node_id.clone(),
                            timestamp: existing_time,
                            operation: existing_entry.operation.clone(),
                        },
                        ConflictingOperation {
                            node_id: message.sender_id.clone(),
                            timestamp: message_time,
                            operation: if let ClusterPayload::CacheOperation { operation, .. } =
                                &message.payload
                            {
                                operation.clone()
                            } else {
                                CacheOp::Update
                            },
                        },
                    ],
                }));
            }
        }

        Ok(None)
    }

    /// Resolve a cache conflict
    async fn resolve_conflict(&self, conflict: CacheConflict) -> Result<(), CoherenceError> {
        match self.config.conflict_resolution {
            ConflictResolution::LastWriterWins => {
                // Find the operation with the latest timestamp
                let latest_op = conflict
                    .conflicting_operations
                    .iter()
                    .max_by_key(|op| op.timestamp)
                    .unwrap();

                debug!(
                    "Conflict resolved: last writer wins ({})",
                    latest_op.node_id
                );
                // Apply the latest operation
            }
            ConflictResolution::FirstWriterWins => {
                // Find the operation with the earliest timestamp
                let first_op = conflict
                    .conflicting_operations
                    .iter()
                    .min_by_key(|op| op.timestamp)
                    .unwrap();

                debug!(
                    "Conflict resolved: first writer wins ({})",
                    first_op.node_id
                );
                // Apply the first operation
            }
            ConflictResolution::VectorClock => {
                // Use vector clocks for conflict resolution
                debug!("Using vector clock for conflict resolution");
                self.resolve_with_vector_clock(&conflict).await?;
            }
            ConflictResolution::Manual => {
                // Return error for manual resolution
                return Err(CoherenceError::ConflictRequiresManualResolution(conflict));
            }
        }

        Ok(())
    }

    /// Resolve conflict using vector clocks
    async fn resolve_with_vector_clock(
        &self,
        conflict: &CacheConflict,
    ) -> Result<(), CoherenceError> {
        let vector_clocks = self.conflict_resolver.vector_clocks.read().await;

        // Compare vector clocks to determine causality
        for op in &conflict.conflicting_operations {
            if let Some(clock) = vector_clocks.get(&op.node_id) {
                debug!("Vector clock for {}: {:?}", op.node_id, clock);
                // Implement vector clock comparison logic
            }
        }

        Ok(())
    }

    /// Update invalidation log
    async fn update_invalidation_log(
        &self,
        key: String,
        operation: CacheOp,
        message: ClusterMessage,
    ) {
        let mut log = self.invalidation_log.write().await;

        let entry = InvalidationEntry {
            key: key.clone(),
            operation,
            timestamp: Instant::now(),
            node_id: message.sender_id,
            version: log.sequence,
            acknowledged_by: HashSet::new(),
        };

        log.entries.insert(key, entry);
        log.sequence += 1;

        // Cleanup old entries
        let retention_cutoff = Instant::now() - self.config.log_retention_time;
        log.entries
            .retain(|_, entry| entry.timestamp > retention_cutoff);
    }

    /// Get coherence statistics
    pub fn stats(&self) -> CoherenceStatsSnapshot {
        CoherenceStatsSnapshot {
            invalidations_sent: self
                .stats
                .invalidations_sent
                .load(std::sync::atomic::Ordering::Relaxed),
            invalidations_received: self
                .stats
                .invalidations_received
                .load(std::sync::atomic::Ordering::Relaxed),
            conflicts_detected: self
                .stats
                .conflicts_detected
                .load(std::sync::atomic::Ordering::Relaxed),
            conflicts_resolved: self
                .stats
                .conflicts_resolved
                .load(std::sync::atomic::Ordering::Relaxed),
            sync_operations: self
                .stats
                .sync_operations
                .load(std::sync::atomic::Ordering::Relaxed),
            failed_invalidations: self
                .stats
                .failed_invalidations
                .load(std::sync::atomic::Ordering::Relaxed),
            dirty_keys_count: self.dirty_keys.len(),
        }
    }
}

/// Cache conflict information
#[derive(Debug, Clone)]
pub struct CacheConflict {
    pub key: String,
    pub conflicting_operations: Vec<ConflictingOperation>,
}

/// Conflicting cache operation
#[derive(Debug, Clone)]
pub struct ConflictingOperation {
    pub node_id: String,
    pub timestamp: std::time::SystemTime,
    pub operation: CacheOp,
}

/// Coherence statistics snapshot
#[derive(Debug, Clone)]
pub struct CoherenceStatsSnapshot {
    pub invalidations_sent: u64,
    pub invalidations_received: u64,
    pub conflicts_detected: u64,
    pub conflicts_resolved: u64,
    pub sync_operations: u64,
    pub failed_invalidations: u64,
    pub dirty_keys_count: usize,
}

impl ConflictResolver {
    fn new(config: CoherenceConfig) -> Self {
        Self {
            config,
            vector_clocks: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl VectorClock {
    fn new() -> Self {
        Self {
            clocks: HashMap::new(),
        }
    }

    fn increment(&mut self, node_id: &str) {
        *self.clocks.entry(node_id.to_string()).or_insert(0) += 1;
    }

    fn update(&mut self, other: &VectorClock) {
        for (node_id, clock) in &other.clocks {
            let current = self.clocks.entry(node_id.clone()).or_insert(0);
            *current = (*current).max(*clock);
        }
    }

    fn happens_before(&self, other: &VectorClock) -> bool {
        let mut all_less_or_equal = true;
        let mut at_least_one_less = false;

        for (node_id, our_clock) in &self.clocks {
            let other_clock = other.clocks.get(node_id).unwrap_or(&0);
            if our_clock > other_clock {
                all_less_or_equal = false;
                break;
            } else if our_clock < other_clock {
                at_least_one_less = true;
            }
        }

        all_less_or_equal && at_least_one_less
    }

    fn concurrent_with(&self, other: &VectorClock) -> bool {
        !self.happens_before(other) && !other.happens_before(self)
    }
}

/// Coherence error types
#[derive(Debug, thiserror::Error)]
pub enum CoherenceError {
    #[error("Network error: {0}")]
    Network(#[from] super::ClusterError),

    #[error("Conflict requires manual resolution: {0:?}")]
    ConflictRequiresManualResolution(CacheConflict),

    #[error("Invalidation timeout for key: {0}")]
    InvalidationTimeout(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_clock_operations() {
        let mut clock1 = VectorClock::new();
        let mut clock2 = VectorClock::new();

        // Initial state - concurrent
        assert!(clock1.concurrent_with(&clock2));

        // Node1 increments
        clock1.increment("node1");
        assert!(clock1.happens_before(&clock2) == false);
        assert!(clock2.happens_before(&clock1));

        // Node2 increments
        clock2.increment("node2");
        assert!(clock1.concurrent_with(&clock2));

        // Node1 updates with node2's clock
        clock1.update(&clock2);
        clock1.increment("node1");
        assert!(clock2.happens_before(&clock1));
    }

    #[tokio::test]
    async fn test_coherence_config() {
        let config = CoherenceConfig::default();
        assert_eq!(config.strategy, CoherenceStrategy::WriteBehind);
        assert_eq!(
            config.conflict_resolution,
            ConflictResolution::LastWriterWins
        );
        assert!(config.conflict_detection);
    }

    #[test]
    fn test_cache_conflict() {
        let conflict = CacheConflict {
            key: "test_key".to_string(),
            conflicting_operations: vec![
                ConflictingOperation {
                    node_id: "node1".to_string(),
                    timestamp: std::time::UNIX_EPOCH,
                    operation: CacheOp::Update,
                },
                ConflictingOperation {
                    node_id: "node2".to_string(),
                    timestamp: std::time::UNIX_EPOCH + Duration::from_secs(1),
                    operation: CacheOp::Update,
                },
            ],
        };

        assert_eq!(conflict.key, "test_key");
        assert_eq!(conflict.conflicting_operations.len(), 2);
    }
}
