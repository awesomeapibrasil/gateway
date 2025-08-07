# Distributed Cache Implementation Plan

## Overview

This document outlines the detailed implementation plan for enhancing the gateway's cache system with distributed capabilities, UDP multicast clustering, and advanced eviction strategies.

## Current State Analysis

### Existing Cache Implementation (`gateway-cache`)

**Strengths:**
- ✅ Basic DashMap-based in-memory cache
- ✅ Redis integration for external caching
- ✅ Database persistence support
- ✅ Basic LRU eviction with access tracking
- ✅ Compression framework (placeholder)
- ✅ TTL support with expiration

**Limitations:**
- ❌ No distributed clustering capabilities
- ❌ Simple LRU without advanced algorithms
- ❌ No UDP multicast communication
- ❌ No protocol-specific optimizations
- ❌ No incremental cleanup strategies
- ❌ Limited metrics and monitoring

## Implementation Plan

### Phase 1: Enhanced Memory Cache (Week 1-2)

#### 1.1 Segmented LRU Implementation

**File**: `crates/gateway-cache/src/segmented_lru.rs`

```rust
pub struct SegmentedLRU<K, V> {
    segments: Vec<Mutex<LRUSegment<K, V>>>,
    segment_count: usize,
    max_size_per_segment: usize,
}

pub struct LRUSegment<K, V> {
    map: HashMap<K, Box<LRUNode<K, V>>>,
    head: *mut LRUNode<K, V>,
    tail: *mut LRUNode<K, V>,
    size: usize,
    max_size: usize,
}
```

**Benefits:**
- Reduced lock contention (parallel segment access)
- Better CPU cache locality
- Scales with number of cores

#### 1.2 Approximated LRU with Random Sampling

**File**: `crates/gateway-cache/src/approximated_lru.rs`

```rust
pub struct ApproximatedLRU<K, V> {
    map: DashMap<K, CacheEntry<V>>,
    config: ApproximatedLRUConfig,
    global_clock: AtomicU64,
    rng: ThreadLocal<RefCell<SmallRng>>,
}

pub struct ApproximatedLRUConfig {
    pub sample_size: usize,        // Default: 5
    pub max_idle_time: Duration,   // Default: 1 hour
    pub eviction_batch_size: usize, // Default: 20
}
```

**Algorithm:**
1. When eviction needed, sample N random keys
2. Select least recently used from sample
3. Remove in batches for efficiency
4. 95% efficiency of true LRU with much better performance

#### 1.3 Incremental Cleanup Engine

**File**: `crates/gateway-cache/src/incremental_cleaner.rs`

```rust
pub struct IncrementalCleaner {
    config: CleanupConfig,
    stats: CleanupStats,
}

pub struct CleanupConfig {
    pub max_cleanup_time_ms: u64,      // Default: 25ms  
    pub cleanup_percentage: f64,        // Default: 20%
    pub min_keys_per_cycle: usize,      // Default: 20
    pub max_keys_per_cycle: usize,      // Default: 100
    pub adaptive_mode: bool,            // Default: true
}

impl IncrementalCleaner {
    pub async fn run_cleanup_cycle(&self, cache: &CacheMap) -> CleanupResult {
        let aggressiveness = self.calculate_aggressiveness(cache.metrics());
        let max_time = Duration::from_millis(
            (self.config.max_cleanup_time_ms as f64 * aggressiveness) as u64
        );
        
        let mut cleaned = 0;
        let start_time = Instant::now();
        
        while start_time.elapsed() < max_time && cleaned < self.config.max_keys_per_cycle {
            if let Some(expired_key) = self.find_expired_key(cache) {
                cache.remove(&expired_key);
                cleaned += 1;
            } else {
                break;
            }
        }
        
        CleanupResult { keys_cleaned: cleaned, time_taken: start_time.elapsed() }
    }
}
```

### Phase 2: UDP Multicast Clustering (Week 2-3)

#### 2.1 Cluster Communication Protocol

**File**: `crates/gateway-cache/src/cluster/mod.rs`

```rust
pub struct UDPMulticastCluster {
    node_id: String,
    multicast_addr: SocketAddr,
    socket: UdpSocket,
    cluster_view: Arc<RwLock<ClusterView>>,
    message_handler: MessageHandler,
    heartbeat_task: JoinHandle<()>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClusterMessage {
    pub message_id: Uuid,
    pub message_type: MessageType,
    pub sender_id: String,
    pub timestamp: u64,
    pub sequence: u64,
    pub payload: ClusterPayload,
    pub checksum: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MessageType {
    Heartbeat,
    NodeJoin,
    NodeLeave,
    CacheInvalidate,
    CacheUpdate,
    ViewChange,
    HealthCheck,
}
```

#### 2.2 Node Discovery and Membership

**File**: `crates/gateway-cache/src/cluster/membership.rs`

```rust
pub struct ClusterView {
    pub nodes: HashMap<String, NodeInfo>,
    pub version: u64,
    pub leader: Option<String>,
    pub last_updated: Instant,
}

pub struct NodeInfo {
    pub node_id: String,
    pub address: SocketAddr,
    pub last_seen: Instant,
    pub load: f64,
    pub memory_usage: f64,
    pub cache_size: usize,
    pub status: NodeStatus,
}

impl UDPMulticastCluster {
    pub async fn join_cluster(&self) -> Result<(), ClusterError> {
        let join_message = ClusterMessage {
            message_type: MessageType::NodeJoin,
            sender_id: self.node_id.clone(),
            payload: ClusterPayload::NodeInfo {
                node_info: self.get_local_node_info(),
            },
            // ... other fields
        };
        
        self.send_multicast_message(join_message).await?;
        self.start_heartbeat_task().await;
        Ok(())
    }
}
```

#### 2.3 Cache Coherence Strategies

**File**: `crates/gateway-cache/src/cluster/coherence.rs`

```rust
pub enum CoherenceStrategy {
    WriteThrough,        // Immediate invalidation
    WriteBehind,         // Periodic sync
    WriteAround,         // Direct to persistent store
}

pub struct CacheCoherenceManager {
    strategy: CoherenceStrategy,
    cluster: Arc<UDPMulticastCluster>,
    dirty_keys: Arc<DashSet<String>>,
    sync_interval: Duration,
}

impl CacheCoherenceManager {
    pub async fn handle_cache_write(&self, key: String, value: Vec<u8>) -> Result<(), CoherenceError> {
        match self.strategy {
            CoherenceStrategy::WriteThrough => {
                self.invalidate_cluster_key(&key).await?;
            },
            CoherenceStrategy::WriteBehind => {
                self.dirty_keys.insert(key);
            },
            CoherenceStrategy::WriteAround => {
                // Write directly to persistent store, skip cache
            },
        }
        Ok(())
    }
    
    pub async fn periodic_sync(&self) {
        let dirty_keys: Vec<String> = self.dirty_keys.iter().map(|k| k.clone()).collect();
        self.dirty_keys.clear();
        
        for key in dirty_keys {
            let sync_message = ClusterMessage {
                message_type: MessageType::CacheUpdate,
                payload: ClusterPayload::CacheOperation {
                    key: key.clone(),
                    operation: CacheOp::Sync,
                },
                // ... other fields
            };
            
            self.cluster.send_multicast_message(sync_message).await.ok();
        }
    }
}
```

### Phase 3: Protocol-Specific Optimizations (Week 3-4)

#### 3.1 HTTP Cache Optimizations

**File**: `crates/gateway-cache/src/http/mod.rs`

```rust
pub struct HTTPCacheManager {
    cache: Arc<DistributedCache>,
    policy_parser: CachePolicyParser,
    vary_handler: VaryHeaderHandler,
}

pub struct HTTPCacheKey {
    pub uri: String,
    pub method: String,
    pub vary_hash: Option<u64>,
    pub query_hash: Option<u64>,
}

impl HTTPCacheManager {
    pub async fn should_cache_request(&self, request: &Request) -> bool {
        // Check cache-control headers
        if let Some(cache_control) = request.headers().get("cache-control") {
            let policy = self.policy_parser.parse(cache_control);
            if policy.no_cache || policy.no_store {
                return false;
            }
        }
        
        // Only cache safe methods
        matches!(request.method(), &Method::GET | &Method::HEAD | &Method::OPTIONS)
    }
    
    pub fn generate_cache_key(&self, request: &Request) -> HTTPCacheKey {
        let mut key = HTTPCacheKey {
            uri: request.uri().to_string(),
            method: request.method().to_string(),
            vary_hash: None,
            query_hash: None,
        };
        
        // Handle Vary header
        if let Some(vary_header) = request.headers().get("vary") {
            key.vary_hash = Some(self.vary_handler.calculate_vary_hash(request, vary_header));
        }
        
        // Hash query parameters for GET requests
        if request.method() == Method::GET && !request.uri().query().unwrap_or("").is_empty() {
            key.query_hash = Some(self.hash_query_params(request.uri().query().unwrap()));
        }
        
        key
    }
}
```

#### 3.2 gRPC Cache Optimizations

**File**: `crates/gateway-cache/src/grpc/mod.rs`

```rust
pub struct GRPCCacheManager {
    cache: Arc<DistributedCache>,
    method_policies: HashMap<String, CachePolicy>,
}

pub struct GRPCCacheKey {
    pub service: String,
    pub method: String,
    pub message_hash: u64,
    pub metadata_hash: u64,
}

impl GRPCCacheManager {
    pub fn should_cache_method(&self, method: &str) -> bool {
        // Cache idempotent methods by default
        if method.starts_with("Get") || method.starts_with("List") || method.starts_with("Search") {
            return true;
        }
        
        // Check custom policies
        self.method_policies.get(method)
            .map(|policy| policy.cacheable)
            .unwrap_or(false)
    }
    
    pub fn generate_cache_key(&self, request: &GRPCRequest) -> GRPCCacheKey {
        let message_hash = self.hash_protobuf_message(&request.message);
        let metadata_hash = self.hash_metadata(&request.metadata);
        
        GRPCCacheKey {
            service: request.service.clone(),
            method: request.method.clone(),
            message_hash,
            metadata_hash,
        }
    }
}
```

### Phase 4: Enhanced Cache Manager Integration (Week 4-5)

#### 4.1 Updated Cache Manager

**File**: `crates/gateway-cache/src/lib.rs` (Enhanced)

```rust
pub struct DistributedCacheManager {
    // Core components
    local_cache: Arc<dyn LocalCache<String, CacheEntry>>,
    cluster: Option<Arc<UDPMulticastCluster>>,
    redis_client: Option<RedisClient>,
    database: Arc<gateway_database::DatabaseManager>,
    
    // Protocol handlers
    http_cache: HTTPCacheManager,
    grpc_cache: GRPCCacheManager,
    
    // Background services
    cleaner: IncrementalCleaner,
    coherence_manager: CacheCoherenceManager,
    metrics_collector: CacheMetricsCollector,
    
    // Configuration
    config: DistributedCacheConfig,
}

impl DistributedCacheManager {
    pub async fn new(config: DistributedCacheConfig) -> Result<Self, CacheError> {
        // Initialize local cache based on algorithm
        let local_cache: Arc<dyn LocalCache<String, CacheEntry>> = match config.local.algorithm {
            LocalCacheAlgorithm::SegmentedLRU => {
                Arc::new(SegmentedLRU::new(config.local.segments, config.local.max_size))
            },
            LocalCacheAlgorithm::ApproximatedLRU => {
                Arc::new(ApproximatedLRU::new(config.local.approximated_config.clone()))
            },
            LocalCacheAlgorithm::DashMap => {
                Arc::new(DashMapCache::new(config.local.max_size))
            },
        };
        
        // Initialize cluster if enabled
        let cluster = if config.distributed.enabled {
            let cluster = UDPMulticastCluster::new(config.distributed.cluster.clone()).await?;
            cluster.join_cluster().await?;
            Some(Arc::new(cluster))
        } else {
            None
        };
        
        // Initialize other components...
        
        Ok(Self {
            local_cache,
            cluster,
            // ... other fields
        })
    }
    
    pub async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        // L1: Try local cache first
        if let Some(entry) = self.local_cache.get(key) {
            if !entry.is_expired() {
                self.metrics_collector.record_hit(CacheLevel::Local);
                return Ok(Some(entry.data));
            }
        }
        
        // L2: Try cluster cache
        if let Some(ref cluster) = self.cluster {
            if let Some(data) = cluster.get_from_peer(key).await? {
                // Store in local cache for future hits
                self.local_cache.insert(key.to_string(), CacheEntry::new(data.clone()));
                self.metrics_collector.record_hit(CacheLevel::Cluster);
                return Ok(Some(data));
            }
        }
        
        // L3: Try Redis
        if let Some(ref redis) = self.redis_client {
            if let Some(data) = self.get_from_redis(key).await? {
                self.local_cache.insert(key.to_string(), CacheEntry::new(data.clone()));
                self.metrics_collector.record_hit(CacheLevel::Redis);
                return Ok(Some(data));
            }
        }
        
        // L4: Try database
        if let Some(data) = self.get_from_database(key).await? {
            self.local_cache.insert(key.to_string(), CacheEntry::new(data.clone()));
            self.metrics_collector.record_hit(CacheLevel::Database);
            return Ok(Some(data));
        }
        
        self.metrics_collector.record_miss();
        Ok(None)
    }
}
```

### Phase 5: Configuration and Testing (Week 5-6)

#### 5.1 Configuration Structure

**File**: `crates/gateway-cache/src/config.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedCacheConfig {
    pub distributed: DistributedConfig,
    pub local: LocalCacheConfig,
    pub protocols: ProtocolConfig,
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedConfig {
    pub enabled: bool,
    pub cluster: ClusterConfig,
    pub coherence: CoherenceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub multicast_address: String,
    pub heartbeat_interval: Duration,
    pub failure_timeout: Duration,
    pub max_cluster_size: usize,
    pub bind_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCacheConfig {
    pub algorithm: LocalCacheAlgorithm,
    pub max_memory: ByteSize,
    pub segments: usize,
    pub cleanup_interval: Duration,
    pub compression: CompressionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LocalCacheAlgorithm {
    SegmentedLRU,
    ApproximatedLRU,
    DashMap,
}
```

#### 5.2 Comprehensive Testing

**File**: `crates/gateway-cache/src/tests/integration_tests.rs`

```rust
#[tokio::test]
async fn test_distributed_cache_coherence() {
    let config = create_test_cluster_config(3);
    let nodes = create_test_cluster(config).await;
    
    // Write to node 0
    nodes[0].set("test_key", b"test_value").await.unwrap();
    
    // Wait for propagation
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Read from node 1 and 2
    let value1 = nodes[1].get("test_key").await.unwrap();
    let value2 = nodes[2].get("test_key").await.unwrap();
    
    assert_eq!(value1, Some(b"test_value".to_vec()));
    assert_eq!(value2, Some(b"test_value".to_vec()));
}

#[tokio::test]
async fn test_incremental_cleanup_performance() {
    let cache = create_cache_with_size(100_000).await;
    
    // Fill cache with expired entries
    for i in 0..100_000 {
        let entry = CacheEntry {
            data: format!("value_{}", i).into_bytes(),
            expires_at: Instant::now() - Duration::from_secs(1), // Already expired
            ..Default::default()
        };
        cache.local_cache.insert(format!("key_{}", i), entry);
    }
    
    let cleaner = IncrementalCleaner::new(CleanupConfig::default());
    let start = Instant::now();
    
    // Run cleanup cycles until all expired entries are removed
    while cache.local_cache.len() > 0 {
        cleaner.run_cleanup_cycle(&cache.local_cache).await;
    }
    
    let cleanup_time = start.elapsed();
    
    // Should clean up 100K entries in reasonable time (< 5 seconds)
    assert!(cleanup_time < Duration::from_secs(5));
}

#[tokio::test]
async fn test_http_cache_with_vary_headers() {
    let cache_manager = HTTPCacheManager::new(create_test_cache().await);
    
    // Create requests with different Accept-Language headers
    let request1 = create_http_request("/api/data", "en-US");
    let request2 = create_http_request("/api/data", "fr-FR");
    
    let key1 = cache_manager.generate_cache_key(&request1);
    let key2 = cache_manager.generate_cache_key(&request2);
    
    // Keys should be different due to Vary header
    assert_ne!(key1.vary_hash, key2.vary_hash);
}
```

## Deliverables

### Code Deliverables

1. **Enhanced Cache Algorithms**
   - `segmented_lru.rs` - Segmented LRU implementation
   - `approximated_lru.rs` - Redis-inspired sampling LRU
   - `incremental_cleaner.rs` - Adaptive cleanup engine

2. **Distributed Clustering**
   - `cluster/mod.rs` - UDP multicast cluster implementation
   - `cluster/membership.rs` - Node discovery and membership
   - `cluster/coherence.rs` - Cache coherence strategies

3. **Protocol Optimizations**
   - `http/mod.rs` - HTTP-specific cache optimizations
   - `grpc/mod.rs` - gRPC-specific cache optimizations

4. **Integration and Configuration**
   - Enhanced `lib.rs` - Unified distributed cache manager
   - `config.rs` - Comprehensive configuration system
   - `metrics.rs` - Detailed metrics collection

### Documentation Deliverables

1. **Technical Documentation**
   - Architecture diagrams and design decisions
   - API documentation and usage examples
   - Configuration reference guide
   - Performance tuning recommendations

2. **Operational Documentation**
   - Deployment and setup guides
   - Monitoring and alerting setup
   - Troubleshooting guides
   - Capacity planning guidelines

### Testing Deliverables

1. **Unit Tests**
   - Individual component tests
   - Algorithm correctness tests
   - Configuration validation tests

2. **Integration Tests**
   - Multi-node cluster testing
   - Protocol-specific cache testing
   - Failure scenario testing

3. **Performance Tests**
   - Latency and throughput benchmarks
   - Memory usage analysis
   - Scalability testing

4. **Load Tests**
   - Stress testing under high load
   - Cluster stability testing
   - Recovery scenario testing

## Success Metrics

### Performance Metrics

1. **Latency**
   - Local cache hit: < 100μs (P99)
   - Cluster cache hit: < 5ms (P99)
   - Cache miss: < 20ms (P99)

2. **Throughput**
   - Single node: > 100K ops/sec
   - Cluster operations: > 50K ops/sec
   - Multicast messages: > 10K msgs/sec

3. **Reliability**
   - Cache hit ratio: > 90%
   - Cluster consistency: > 99.9%
   - Node availability: > 99.99%

### Functional Requirements

1. **Distributed Caching**
   - ✅ UDP multicast clustering
   - ✅ Automatic node discovery
   - ✅ Cache coherence strategies
   - ✅ Failure detection and recovery

2. **Advanced Eviction**
   - ✅ Segmented LRU implementation
   - ✅ Approximated LRU with sampling
   - ✅ Incremental cleanup strategies
   - ✅ Adaptive cleanup based on load

3. **Protocol Optimization**
   - ✅ HTTP cache-control support
   - ✅ HTTP Vary header handling
   - ✅ gRPC method-based caching
   - ✅ Protocol-specific optimizations

## Risk Mitigation

### Technical Risks

1. **Network Partition Handling**
   - Implement partition tolerance in cluster protocol
   - Graceful degradation to local cache only
   - Automatic recovery when partition heals

2. **Memory Management**
   - Comprehensive memory usage monitoring
   - Automatic cleanup when memory pressure detected
   - Configurable memory limits and alerts

3. **Performance Degradation**
   - Extensive benchmarking and load testing
   - Performance regression testing in CI/CD
   - Gradual rollout with monitoring

### Operational Risks

1. **Configuration Complexity**
   - Sensible defaults for all configuration options
   - Configuration validation and error reporting
   - Comprehensive documentation and examples

2. **Monitoring and Debugging**
   - Detailed metrics and logging
   - Health check endpoints
   - Debug tools and utilities

This implementation plan provides a structured approach to building a world-class distributed cache system while maintaining the existing functionality and ensuring minimal disruption to current operations.