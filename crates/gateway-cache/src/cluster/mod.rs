use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};
use serde::{Deserialize, Serialize};
use tokio::time::{interval, MissedTickBehavior};
use tokio::task::JoinHandle;
use uuid::Uuid;
use tracing::{debug, error, info, warn};
use sha2::{Digest, Sha256};

pub mod membership;
pub mod coherence;

pub use membership::{ClusterView, NodeInfo, NodeStatus};
pub use coherence::{CacheCoherenceManager, CoherenceStrategy};

/// UDP Multicast cluster for distributed cache coordination
pub struct UDPMulticastCluster {
    node_id: String,
    config: ClusterConfig,
    socket: UdpSocket,
    cluster_view: Arc<RwLock<ClusterView>>,
    message_handler: MessageHandler,
    heartbeat_task: Option<JoinHandle<()>>,
    receive_task: Option<JoinHandle<()>>,
    stats: ClusterStats,
}

/// Configuration for UDP multicast clustering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Multicast address and port (e.g., "224.0.1.100:5000")
    pub multicast_address: String,
    /// Local bind address (optional, defaults to 0.0.0.0:0)
    pub bind_address: Option<String>,
    /// Heartbeat interval
    pub heartbeat_interval: Duration,
    /// Node failure timeout
    pub failure_timeout: Duration,
    /// Maximum cluster size
    pub max_cluster_size: usize,
    /// Message retry attempts
    pub message_retry_attempts: u8,
    /// Message timeout
    pub message_timeout: Duration,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            multicast_address: "224.0.1.100:5000".to_string(),
            bind_address: None,
            heartbeat_interval: Duration::from_secs(5),
            failure_timeout: Duration::from_secs(30),
            max_cluster_size: 20,
            message_retry_attempts: 3,
            message_timeout: Duration::from_secs(5),
        }
    }
}

/// Cluster message for UDP multicast communication
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClusterMessage {
    pub message_id: String,
    pub message_type: MessageType,
    pub sender_id: String,
    pub timestamp: u64,
    pub sequence: u64,
    pub payload: ClusterPayload,
    pub checksum: String,
}

/// Types of cluster messages
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum MessageType {
    Heartbeat,
    NodeJoin,
    NodeLeave,
    CacheInvalidate,
    CacheUpdate,
    ViewChange,
    HealthCheck,
    Ping,
    Pong,
}

/// Payload of cluster messages
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ClusterPayload {
    Heartbeat { 
        load: f64, 
        memory_usage: f64,
        cache_size: usize,
    },
    NodeInfo { 
        node_info: NodeInfo,
    },
    CacheOperation { 
        key: String, 
        operation: CacheOp,
        data: Option<Vec<u8>>,
    },
    ViewUpdate { 
        view: ClusterView,
    },
    HealthStatus {
        status: String,
        metrics: HashMap<String, f64>,
    },
    PingPong {
        request_id: String,
        timestamp: u64,
    },
}

/// Cache operations for cluster coordination
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum CacheOp {
    Invalidate,
    Update,
    Delete,
    Sync,
}

/// Message handler for processing cluster messages
pub struct MessageHandler {
    node_id: String,
    cluster_view: Arc<RwLock<ClusterView>>,
    message_sequence: Arc<std::sync::atomic::AtomicU64>,
    pending_messages: Arc<RwLock<HashMap<String, PendingMessage>>>,
}

/// Pending message for reliability
#[derive(Debug, Clone)]
pub struct PendingMessage {
    pub message: ClusterMessage,
    pub sent_at: Instant,
    pub retry_count: u8,
    pub max_retries: u8,
}

/// Cluster statistics
#[derive(Debug, Default)]
pub struct ClusterStats {
    pub messages_sent: std::sync::atomic::AtomicU64,
    pub messages_received: std::sync::atomic::AtomicU64,
    pub heartbeats_sent: std::sync::atomic::AtomicU64,
    pub heartbeats_received: std::sync::atomic::AtomicU64,
    pub cache_operations_sent: std::sync::atomic::AtomicU64,
    pub cache_operations_received: std::sync::atomic::AtomicU64,
    pub message_send_errors: std::sync::atomic::AtomicU64,
    pub message_receive_errors: std::sync::atomic::AtomicU64,
}

impl UDPMulticastCluster {
    /// Create a new UDP multicast cluster
    pub async fn new(config: ClusterConfig) -> Result<Self, ClusterError> {
        let node_id = Uuid::new_v4().to_string();
        
        // Parse multicast address
        let multicast_addr: SocketAddr = config.multicast_address
            .parse()
            .map_err(|e| ClusterError::Configuration(format!("Invalid multicast address: {}", e)))?;
        
        // Create UDP socket
        let bind_addr = if let Some(ref bind_address) = config.bind_address {
            bind_address.parse().map_err(|e| ClusterError::Configuration(format!("Invalid bind address: {}", e)))?
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        
        let socket = UdpSocket::bind(bind_addr)
            .map_err(|e| ClusterError::Network(format!("Failed to bind socket: {}", e)))?;
        
        // Join multicast group
        if let IpAddr::V4(multicast_ip) = multicast_addr.ip() {
            socket.join_multicast_v4(&multicast_ip, &Ipv4Addr::UNSPECIFIED)
                .map_err(|e| ClusterError::Network(format!("Failed to join multicast group: {}", e)))?;
        } else {
            return Err(ClusterError::Configuration("Only IPv4 multicast is supported".to_string()));
        }
        
        socket.set_multicast_loop_v4(false)
            .map_err(|e| ClusterError::Network(format!("Failed to disable multicast loop: {}", e)))?;
        
        socket.set_nonblocking(true)
            .map_err(|e| ClusterError::Network(format!("Failed to set non-blocking: {}", e)))?;
        
        let cluster_view = Arc::new(RwLock::new(ClusterView::new()));
        let message_handler = MessageHandler::new(node_id.clone(), Arc::clone(&cluster_view));
        
        Ok(Self {
            node_id,
            config,
            socket,
            cluster_view,
            message_handler,
            heartbeat_task: None,
            receive_task: None,
            stats: ClusterStats::default(),
        })
    }
    
    /// Join the cluster
    pub async fn join_cluster(&mut self) -> Result<(), ClusterError> {
        info!("Node {} joining cluster at {}", self.node_id, self.config.multicast_address);
        
        // Add self to cluster view
        {
            let mut view = self.cluster_view.write().unwrap();
            let local_addr = self.socket.local_addr()
                .map_err(|e| ClusterError::Network(format!("Failed to get local address: {}", e)))?;
            
            let node_info = NodeInfo {
                node_id: self.node_id.clone(),
                address: local_addr,
                last_seen: Instant::now(),
                load: 0.0,
                memory_usage: 0.0,
                cache_size: 0,
                status: NodeStatus::Active,
            };
            
            view.add_node(node_info);
        }
        
        // Send join message
        let join_message = ClusterMessage {
            message_id: Uuid::new_v4().to_string(),
            message_type: MessageType::NodeJoin,
            sender_id: self.node_id.clone(),
            timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
            sequence: self.message_handler.next_sequence(),
            payload: ClusterPayload::NodeInfo {
                node_info: self.get_local_node_info()?,
            },
            checksum: String::new(),
        };
        
        self.send_multicast_message(join_message).await?;
        
        // Start background tasks
        self.start_heartbeat_task().await;
        self.start_receive_task().await;
        
        info!("Node {} successfully joined cluster", self.node_id);
        Ok(())
    }
    
    /// Leave the cluster
    pub async fn leave_cluster(&mut self) -> Result<(), ClusterError> {
        info!("Node {} leaving cluster", self.node_id);
        
        // Send leave message
        let leave_message = ClusterMessage {
            message_id: Uuid::new_v4().to_string(),
            message_type: MessageType::NodeLeave,
            sender_id: self.node_id.clone(),
            timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
            sequence: self.message_handler.next_sequence(),
            payload: ClusterPayload::NodeInfo {
                node_info: self.get_local_node_info()?,
            },
            checksum: String::new(),
        };
        
        self.send_multicast_message(leave_message).await?;
        
        // Stop background tasks
        if let Some(task) = self.heartbeat_task.take() {
            task.abort();
        }
        if let Some(task) = self.receive_task.take() {
            task.abort();
        }
        
        // Remove self from cluster view
        {
            let mut view = self.cluster_view.write().unwrap();
            view.remove_node(&self.node_id);
        }
        
        info!("Node {} left cluster", self.node_id);
        Ok(())
    }
    
    /// Send a multicast message
    pub async fn send_multicast_message(&self, mut message: ClusterMessage) -> Result<(), ClusterError> {
        // Calculate checksum
        message.checksum = self.calculate_message_checksum(&message);
        
        // Serialize message
        let data = serde_json::to_vec(&message)
            .map_err(|e| ClusterError::Serialization(format!("Failed to serialize message: {}", e)))?;
        
        // Send to multicast address
        let multicast_addr: SocketAddr = self.config.multicast_address.parse().unwrap();
        
        match self.socket.send_to(&data, multicast_addr) {
            Ok(bytes_sent) => {
                debug!("Sent {} bytes to multicast group: {:?}", bytes_sent, message.message_type);
                self.stats.messages_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                
                if message.message_type == MessageType::Heartbeat {
                    self.stats.heartbeats_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                } else if matches!(message.message_type, MessageType::CacheInvalidate | MessageType::CacheUpdate) {
                    self.stats.cache_operations_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                
                Ok(())
            }
            Err(e) => {
                self.stats.message_send_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(ClusterError::Network(format!("Failed to send message: {}", e)))
            }
        }
    }
    
    /// Get local node information
    fn get_local_node_info(&self) -> Result<NodeInfo, ClusterError> {
        let local_addr = self.socket.local_addr()
            .map_err(|e| ClusterError::Network(format!("Failed to get local address: {}", e)))?;
        
        Ok(NodeInfo {
            node_id: self.node_id.clone(),
            address: local_addr,
            last_seen: Instant::now(),
            load: self.get_system_load(),
            memory_usage: self.get_memory_usage(),
            cache_size: 0, // Will be updated by cache manager
            status: NodeStatus::Active,
        })
    }
    
    /// Start heartbeat task
    async fn start_heartbeat_task(&mut self) {
        let node_id = self.node_id.clone();
        let cluster = self.clone_for_task();
        let heartbeat_interval = self.config.heartbeat_interval;
        
        let task = tokio::spawn(async move {
            let mut interval = interval(heartbeat_interval);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            
            loop {
                interval.tick().await;
                
                let heartbeat_message = ClusterMessage {
                    message_id: Uuid::new_v4().to_string(),
                    message_type: MessageType::Heartbeat,
                    sender_id: node_id.clone(),
                    timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
                    sequence: cluster.message_handler.next_sequence(),
                    payload: ClusterPayload::Heartbeat {
                        load: cluster.get_system_load(),
                        memory_usage: cluster.get_memory_usage(),
                        cache_size: 0, // Updated by cache manager
                    },
                    checksum: String::new(),
                };
                
                if let Err(e) = cluster.send_multicast_message(heartbeat_message).await {
                    warn!("Failed to send heartbeat: {}", e);
                }
            }
        });
        
        self.heartbeat_task = Some(task);
    }
    
    /// Start message receive task
    async fn start_receive_task(&mut self) {
        let cluster = self.clone_for_task();
        
        let task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 65536]; // 64KB buffer
            
            loop {
                match cluster.socket.recv_from(&mut buffer) {
                    Ok((bytes_received, sender_addr)) => {
                        if let Err(e) = cluster.handle_received_message(&buffer[..bytes_received], sender_addr).await {
                            warn!("Failed to handle received message: {}", e);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No data available, sleep briefly
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(e) => {
                        error!("Failed to receive message: {}", e);
                        cluster.stats.message_receive_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
        
        self.receive_task = Some(task);
    }
    
    /// Handle received message
    async fn handle_received_message(&self, data: &[u8], sender_addr: SocketAddr) -> Result<(), ClusterError> {
        // Deserialize message
        let message: ClusterMessage = serde_json::from_slice(data)
            .map_err(|e| ClusterError::Serialization(format!("Failed to deserialize message: {}", e)))?;
        
        // Ignore messages from self
        if message.sender_id == self.node_id {
            return Ok(());
        }
        
        // Verify checksum
        if !self.verify_message_checksum(&message) {
            warn!("Received message with invalid checksum from {}", message.sender_id);
            return Err(ClusterError::InvalidMessage("Invalid checksum".to_string()));
        }
        
        debug!("Received {:?} message from {}", message.message_type, message.sender_id);
        
        self.stats.messages_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        if message.message_type == MessageType::Heartbeat {
            self.stats.heartbeats_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else if matches!(message.message_type, MessageType::CacheInvalidate | MessageType::CacheUpdate) {
            self.stats.cache_operations_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        
        // Process message
        self.message_handler.handle_message(message, sender_addr).await
    }
    
    /// Calculate message checksum
    fn calculate_message_checksum(&self, message: &ClusterMessage) -> String {
        let mut hasher = Sha256::new();
        hasher.update(message.message_id.as_bytes());
        hasher.update(message.sender_id.as_bytes());
        hasher.update(message.timestamp.to_be_bytes());
        hasher.update(message.sequence.to_be_bytes());
        hasher.update(format!("{:?}", message.message_type).as_bytes());
        hasher.update(serde_json::to_string(&message.payload).unwrap_or_default().as_bytes());
        format!("{:x}", hasher.finalize())
    }
    
    /// Verify message checksum
    fn verify_message_checksum(&self, message: &ClusterMessage) -> bool {
        let mut message_copy = message.clone();
        message_copy.checksum = String::new();
        let calculated_checksum = self.calculate_message_checksum(&message_copy);
        calculated_checksum == message.checksum
    }
    
    /// Get system load (mock implementation)
    fn get_system_load(&self) -> f64 {
        // In a real implementation, this would get actual system load
        rand::random::<f64>() * 0.1 + 0.1 // Mock load between 0.1 and 0.2
    }
    
    /// Get memory usage (mock implementation)
    fn get_memory_usage(&self) -> f64 {
        // In a real implementation, this would get actual memory usage
        rand::random::<f64>() * 0.3 + 0.3 // Mock usage between 0.3 and 0.6
    }
    
    /// Clone for background tasks
    fn clone_for_task(&self) -> Self {
        Self {
            node_id: self.node_id.clone(),
            config: self.config.clone(),
            socket: self.socket.try_clone().unwrap(),
            cluster_view: Arc::clone(&self.cluster_view),
            message_handler: self.message_handler.clone(),
            heartbeat_task: None,
            receive_task: None,
            stats: ClusterStats::default(), // New stats for task
        }
    }
    
    /// Get cluster statistics
    pub fn stats(&self) -> ClusterStatsSnapshot {
        ClusterStatsSnapshot {
            messages_sent: self.stats.messages_sent.load(std::sync::atomic::Ordering::Relaxed),
            messages_received: self.stats.messages_received.load(std::sync::atomic::Ordering::Relaxed),
            heartbeats_sent: self.stats.heartbeats_sent.load(std::sync::atomic::Ordering::Relaxed),
            heartbeats_received: self.stats.heartbeats_received.load(std::sync::atomic::Ordering::Relaxed),
            cache_operations_sent: self.stats.cache_operations_sent.load(std::sync::atomic::Ordering::Relaxed),
            cache_operations_received: self.stats.cache_operations_received.load(std::sync::atomic::Ordering::Relaxed),
            message_send_errors: self.stats.message_send_errors.load(std::sync::atomic::Ordering::Relaxed),
            message_receive_errors: self.stats.message_receive_errors.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
    
    /// Get current cluster view
    pub fn cluster_view(&self) -> ClusterView {
        self.cluster_view.read().unwrap().clone()
    }
}

impl Drop for UDPMulticastCluster {
    fn drop(&mut self) {
        // Clean shutdown
        if let Some(task) = self.heartbeat_task.take() {
            task.abort();
        }
        if let Some(task) = self.receive_task.take() {
            task.abort();
        }
    }
}

/// Cluster statistics snapshot
#[derive(Debug, Clone)]
pub struct ClusterStatsSnapshot {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub heartbeats_sent: u64,
    pub heartbeats_received: u64,
    pub cache_operations_sent: u64,
    pub cache_operations_received: u64,
    pub message_send_errors: u64,
    pub message_receive_errors: u64,
}

impl MessageHandler {
    fn new(node_id: String, cluster_view: Arc<RwLock<ClusterView>>) -> Self {
        Self {
            node_id,
            cluster_view,
            message_sequence: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pending_messages: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    fn next_sequence(&self) -> u64 {
        self.message_sequence.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
    
    async fn handle_message(&self, message: ClusterMessage, _sender_addr: SocketAddr) -> Result<(), ClusterError> {
        match message.message_type {
            MessageType::Heartbeat => {
                if let ClusterPayload::Heartbeat { load, memory_usage, cache_size } = message.payload {
                    let mut view = self.cluster_view.write().unwrap();
                    view.update_node_metrics(&message.sender_id, load, memory_usage, cache_size);
                }
            }
            MessageType::NodeJoin => {
                if let ClusterPayload::NodeInfo { node_info } = message.payload {
                    let mut view = self.cluster_view.write().unwrap();
                    view.add_node(node_info);
                    info!("Node {} joined the cluster", message.sender_id);
                }
            }
            MessageType::NodeLeave => {
                let mut view = self.cluster_view.write().unwrap();
                view.remove_node(&message.sender_id);
                info!("Node {} left the cluster", message.sender_id);
            }
            MessageType::CacheInvalidate => {
                // Handle cache invalidation
                debug!("Received cache invalidate from {}", message.sender_id);
            }
            MessageType::CacheUpdate => {
                // Handle cache update
                debug!("Received cache update from {}", message.sender_id);
            }
            MessageType::ViewChange => {
                // Handle cluster view change
                debug!("Received view change from {}", message.sender_id);
            }
            MessageType::HealthCheck => {
                // Handle health check
                debug!("Received health check from {}", message.sender_id);
            }
            MessageType::Ping => {
                // Handle ping - respond with pong
                debug!("Received ping from {}", message.sender_id);
            }
            MessageType::Pong => {
                // Handle pong response
                debug!("Received pong from {}", message.sender_id);
            }
        }
        
        Ok(())
    }
    
    fn clone(&self) -> Self {
        Self {
            node_id: self.node_id.clone(),
            cluster_view: Arc::clone(&self.cluster_view),
            message_sequence: Arc::clone(&self.message_sequence),
            pending_messages: Arc::clone(&self.pending_messages),
        }
    }
}

/// Cluster error types
#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
    
    #[error("Timeout: {0}")]
    Timeout(String),
    
    #[error("Node not found: {0}")]
    NodeNotFound(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;
    
    #[tokio::test]
    async fn test_cluster_creation() {
        let config = ClusterConfig {
            multicast_address: "224.0.1.200:5001".to_string(),
            ..Default::default()
        };
        
        let cluster = UDPMulticastCluster::new(config).await;
        assert!(cluster.is_ok());
    }
    
    #[tokio::test]
    async fn test_message_checksum() {
        let config = ClusterConfig::default();
        let cluster = UDPMulticastCluster::new(config).await.unwrap();
        
        let message = ClusterMessage {
            message_id: "test".to_string(),
            message_type: MessageType::Heartbeat,
            sender_id: "node1".to_string(),
            timestamp: 12345,
            sequence: 1,
            payload: ClusterPayload::Heartbeat {
                load: 0.5,
                memory_usage: 0.6,
                cache_size: 100,
            },
            checksum: String::new(),
        };
        
        let checksum = cluster.calculate_message_checksum(&message);
        assert!(!checksum.is_empty());
        
        let mut message_with_checksum = message;
        message_with_checksum.checksum = checksum;
        assert!(cluster.verify_message_checksum(&message_with_checksum));
    }
    
    #[tokio::test]
    async fn test_cluster_join_leave() {
        let config = ClusterConfig {
            multicast_address: "224.0.1.201:5002".to_string(),
            heartbeat_interval: Duration::from_millis(100),
            ..Default::default()
        };
        
        let mut cluster = UDPMulticastCluster::new(config).await.unwrap();
        
        // Join cluster
        assert!(cluster.join_cluster().await.is_ok());
        
        // Check that we're in the cluster view
        let view = cluster.cluster_view();
        assert_eq!(view.nodes.len(), 1);
        assert!(view.nodes.contains_key(&cluster.node_id));
        
        // Wait a bit for heartbeat task to start
        sleep(Duration::from_millis(50)).await;
        
        // Leave cluster
        assert!(cluster.leave_cluster().await.is_ok());
        
        // Check that we're no longer in the cluster view
        let view = cluster.cluster_view();
        assert!(view.nodes.is_empty());
    }
}