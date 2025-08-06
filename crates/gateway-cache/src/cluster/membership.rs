use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// Cluster view containing information about all nodes
#[derive(Debug, Clone)]
pub struct ClusterView {
    pub nodes: HashMap<String, NodeInfo>,
    pub version: u64,
    pub leader: Option<String>,
    pub last_updated: Option<Instant>,
}

impl serde::Serialize for ClusterView {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ClusterView", 3)?;
        state.serialize_field("nodes", &self.nodes)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("leader", &self.leader)?;
        // Skip last_updated since Instant doesn't serialize
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for ClusterView {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ClusterViewHelper {
            nodes: HashMap<String, NodeInfo>,
            version: u64,
            leader: Option<String>,
        }
        
        let helper = ClusterViewHelper::deserialize(deserializer)?;
        Ok(ClusterView {
            nodes: helper.nodes,
            version: helper.version,
            leader: helper.leader,
            last_updated: Some(Instant::now()),
        })
    }
}

/// Information about a cluster node  
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub node_id: String,
    pub address: SocketAddr,
    pub last_seen: Instant,
    pub load: f64,
    pub memory_usage: f64,
    pub cache_size: usize,
    pub status: NodeStatus,
}

impl serde::Serialize for NodeInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("NodeInfo", 6)?;
        state.serialize_field("node_id", &self.node_id)?;
        state.serialize_field("address", &self.address)?;
        state.serialize_field("load", &self.load)?;
        state.serialize_field("memory_usage", &self.memory_usage)?;
        state.serialize_field("cache_size", &self.cache_size)?;
        state.serialize_field("status", &self.status)?;
        // Skip last_seen since Instant doesn't serialize
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for NodeInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct NodeInfoHelper {
            node_id: String,
            address: SocketAddr,
            load: f64,
            memory_usage: f64,
            cache_size: usize,
            status: NodeStatus,
        }
        
        let helper = NodeInfoHelper::deserialize(deserializer)?;
        Ok(NodeInfo {
            node_id: helper.node_id,
            address: helper.address,
            last_seen: Instant::now(),
            load: helper.load,
            memory_usage: helper.memory_usage,
            cache_size: helper.cache_size,
            status: helper.status,
        })
    }
}

/// Status of a cluster node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Copy)]
pub enum NodeStatus {
    Active,
    Inactive,
    Suspect,
    Failed,
    Leaving,
}

impl ClusterView {
    /// Create a new empty cluster view
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            version: 0,
            leader: None,
            last_updated: Some(Instant::now()),
        }
    }
    
    /// Add a node to the cluster view
    pub fn add_node(&mut self, node_info: NodeInfo) {
        let node_id = node_info.node_id.clone();
        self.nodes.insert(node_id.clone(), node_info);
        self.version += 1;
        self.last_updated = Some(Instant::now());
        
        // Update leader if this is the first node or has lower ID
        self.update_leader();
    }
    
    /// Remove a node from the cluster view
    pub fn remove_node(&mut self, node_id: &str) -> Option<NodeInfo> {
        let removed = self.nodes.remove(node_id);
        if removed.is_some() {
            self.version += 1;
            self.last_updated = Some(Instant::now());
            
            // Update leader if the removed node was the leader
            if self.leader.as_ref() == Some(&node_id.to_string()) {
                self.update_leader();
            }
        }
        removed
    }
    
    /// Update node metrics
    pub fn update_node_metrics(&mut self, node_id: &str, load: f64, memory_usage: f64, cache_size: usize) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.load = load;
            node.memory_usage = memory_usage;
            node.cache_size = cache_size;
            node.last_seen = Instant::now();
            node.status = NodeStatus::Active;
            self.last_updated = Some(Instant::now());
        }
    }
    
    /// Mark a node as suspect (potentially failed)
    pub fn mark_node_suspect(&mut self, node_id: &str) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            if node.status == NodeStatus::Active {
                node.status = NodeStatus::Suspect;
                self.version += 1;
                self.last_updated = Some(Instant::now());
            }
        }
    }
    
    /// Mark a node as failed
    pub fn mark_node_failed(&mut self, node_id: &str) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.status = NodeStatus::Failed;
            self.version += 1;
            self.last_updated = Some(Instant::now());
            
            // Update leader if the failed node was the leader
            if self.leader.as_ref() == Some(&node_id.to_string()) {
                self.update_leader();
            }
        }
    }
    
    /// Get active nodes
    pub fn active_nodes(&self) -> Vec<&NodeInfo> {
        self.nodes
            .values()
            .filter(|node| node.status == NodeStatus::Active)
            .collect()
    }
    
    /// Get suspect nodes
    pub fn suspect_nodes(&self) -> Vec<&NodeInfo> {
        self.nodes
            .values()
            .filter(|node| node.status == NodeStatus::Suspect)
            .collect()
    }
    
    /// Get failed nodes
    pub fn failed_nodes(&self) -> Vec<&NodeInfo> {
        self.nodes
            .values()
            .filter(|node| node.status == NodeStatus::Failed)
            .collect()
    }
    
    /// Check for expired nodes based on failure timeout
    pub fn check_expired_nodes(&mut self, failure_timeout: Duration) -> Vec<String> {
        let now = Instant::now();
        let mut expired_nodes = Vec::new();
        
        for (node_id, node) in &mut self.nodes {
            let time_since_last_seen = now.duration_since(node.last_seen);
            
            match node.status {
                NodeStatus::Active if time_since_last_seen > failure_timeout / 2 => {
                    // Mark as suspect if we haven't heard from them for half the failure timeout
                    node.status = NodeStatus::Suspect;
                    self.version += 1;
                }
                NodeStatus::Suspect if time_since_last_seen > failure_timeout => {
                    // Mark as failed if suspect for too long
                    node.status = NodeStatus::Failed;
                    expired_nodes.push(node_id.clone());
                    self.version += 1;
                }
                _ => {}
            }
        }
        
        if !expired_nodes.is_empty() {
            self.last_updated = Some(Instant::now());
            self.update_leader();
        }
        
        expired_nodes
    }
    
    /// Clean up failed nodes older than cleanup timeout
    pub fn cleanup_failed_nodes(&mut self, cleanup_timeout: Duration) -> Vec<String> {
        let now = Instant::now();
        let mut cleaned_nodes = Vec::new();
        
        self.nodes.retain(|node_id, node| {
            if node.status == NodeStatus::Failed {
                let time_since_last_seen = now.duration_since(node.last_seen);
                if time_since_last_seen > cleanup_timeout {
                    cleaned_nodes.push(node_id.clone());
                    false // Remove this node
                } else {
                    true // Keep this node
                }
            } else {
                true // Keep all non-failed nodes
            }
        });
        
        if !cleaned_nodes.is_empty() {
            self.version += 1;
            self.last_updated = Some(Instant::now());
        }
        
        cleaned_nodes
    }
    
    /// Update the cluster leader (node with lowest ID among active nodes)
    fn update_leader(&mut self) {
        self.leader = self.active_nodes()
            .iter()
            .min_by(|a, b| a.node_id.cmp(&b.node_id))
            .map(|node| node.node_id.clone());
    }
    
    /// Check if a node is the current leader
    pub fn is_leader(&self, node_id: &str) -> bool {
        self.leader.as_ref() == Some(&node_id.to_string())
    }
    
    /// Get cluster statistics
    pub fn stats(&self) -> ClusterViewStats {
        let active_count = self.active_nodes().len();
        let suspect_count = self.suspect_nodes().len();
        let failed_count = self.failed_nodes().len();
        
        let total_cache_size = self.active_nodes()
            .iter()
            .map(|node| node.cache_size)
            .sum();
        
        let avg_load = if active_count > 0 {
            self.active_nodes()
                .iter()
                .map(|node| node.load)
                .sum::<f64>() / active_count as f64
        } else {
            0.0
        };
        
        let avg_memory_usage = if active_count > 0 {
            self.active_nodes()
                .iter()
                .map(|node| node.memory_usage)
                .sum::<f64>() / active_count as f64
        } else {
            0.0
        };
        
        ClusterViewStats {
            total_nodes: self.nodes.len(),
            active_nodes: active_count,
            suspect_nodes: suspect_count,
            failed_nodes: failed_count,
            total_cache_size,
            avg_load,
            avg_memory_usage,
            cluster_version: self.version,
            leader: self.leader.clone(),
        }
    }
    
    /// Get node by ID
    pub fn get_node(&self, node_id: &str) -> Option<&NodeInfo> {
        self.nodes.get(node_id)
    }
    
    /// Get all node IDs
    pub fn node_ids(&self) -> Vec<String> {
        self.nodes.keys().cloned().collect()
    }
    
    /// Check if cluster is healthy (majority of nodes are active)
    pub fn is_healthy(&self) -> bool {
        let total_nodes = self.nodes.len();
        let active_nodes = self.active_nodes().len();
        
        if total_nodes == 0 {
            true // Empty cluster is considered healthy
        } else {
            active_nodes * 2 > total_nodes // Majority are active
        }
    }
    
    /// Get the best node for a given key (consistent hashing)
    pub fn get_preferred_node(&self, key: &str) -> Option<&NodeInfo> {
        let active_nodes = self.active_nodes();
        if active_nodes.is_empty() {
            return None;
        }
        
        // Simple hash-based selection
        let hash = self.hash_key(key);
        let index = (hash as usize) % active_nodes.len();
        Some(active_nodes[index])
    }
    
    /// Simple hash function for key distribution
    fn hash_key(&self, key: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }
}

impl Default for ClusterView {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the cluster view
#[derive(Debug, Clone)]
pub struct ClusterViewStats {
    pub total_nodes: usize,
    pub active_nodes: usize,
    pub suspect_nodes: usize,
    pub failed_nodes: usize,
    pub total_cache_size: usize,
    pub avg_load: f64,
    pub avg_memory_usage: f64,
    pub cluster_version: u64,
    pub leader: Option<String>,
}

impl NodeInfo {
    /// Create a new node info
    pub fn new(node_id: String, address: SocketAddr) -> Self {
        Self {
            node_id,
            address,
            last_seen: Instant::now(),
            load: 0.0,
            memory_usage: 0.0,
            cache_size: 0,
            status: NodeStatus::Active,
        }
    }
    
    /// Check if the node is healthy
    pub fn is_healthy(&self) -> bool {
        self.status == NodeStatus::Active && self.load < 0.9 && self.memory_usage < 0.9
    }
    
    /// Get time since last seen
    pub fn time_since_last_seen(&self) -> Duration {
        Instant::now().duration_since(self.last_seen)
    }
    
    /// Update node status
    pub fn update_status(&mut self, status: NodeStatus) {
        self.status = status;
        if status == NodeStatus::Active {
            self.last_seen = Instant::now();
        }
    }
    
    /// Calculate node score for load balancing (lower is better)
    pub fn load_score(&self) -> f64 {
        match self.status {
            NodeStatus::Active => {
                // Combine load and memory usage
                (self.load * 0.6) + (self.memory_usage * 0.4)
            }
            NodeStatus::Suspect => 1.5, // Higher penalty for suspect nodes
            _ => f64::INFINITY, // Don't use failed/inactive nodes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    fn create_test_node(id: &str, port: u16) -> NodeInfo {
        NodeInfo::new(
            id.to_string(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        )
    }
    
    #[test]
    fn test_cluster_view_basic_operations() {
        let mut view = ClusterView::new();
        assert_eq!(view.nodes.len(), 0);
        assert_eq!(view.version, 0);
        
        // Add a node
        let node1 = create_test_node("node1", 5001);
        view.add_node(node1.clone());
        
        assert_eq!(view.nodes.len(), 1);
        assert_eq!(view.version, 1);
        assert_eq!(view.leader, Some("node1".to_string()));
        
        // Add another node
        let node2 = create_test_node("node2", 5002);
        view.add_node(node2);
        
        assert_eq!(view.nodes.len(), 2);
        assert_eq!(view.version, 2);
        
        // Remove a node
        let removed = view.remove_node("node1");
        assert!(removed.is_some());
        assert_eq!(view.nodes.len(), 1);
        assert_eq!(view.version, 3);
        assert_eq!(view.leader, Some("node2".to_string()));
    }
    
    #[test]
    fn test_leader_election() {
        let mut view = ClusterView::new();
        
        // Add nodes in different order
        let node_c = create_test_node("node_c", 5003);
        let node_a = create_test_node("node_a", 5001);
        let node_b = create_test_node("node_b", 5002);
        
        view.add_node(node_c);
        assert_eq!(view.leader, Some("node_c".to_string()));
        
        view.add_node(node_a);
        assert_eq!(view.leader, Some("node_a".to_string())); // node_a has lowest ID
        
        view.add_node(node_b);
        assert_eq!(view.leader, Some("node_a".to_string())); // Still node_a
        
        // Remove leader
        view.remove_node("node_a");
        assert_eq!(view.leader, Some("node_b".to_string())); // Next lowest ID
    }
    
    #[test]
    fn test_node_status_transitions() {
        let mut view = ClusterView::new();
        let node = create_test_node("test_node", 5001);
        view.add_node(node);
        
        // Initially active
        assert_eq!(view.get_node("test_node").unwrap().status, NodeStatus::Active);
        
        // Mark as suspect
        view.mark_node_suspect("test_node");
        assert_eq!(view.get_node("test_node").unwrap().status, NodeStatus::Suspect);
        
        // Mark as failed
        view.mark_node_failed("test_node");
        assert_eq!(view.get_node("test_node").unwrap().status, NodeStatus::Failed);
    }
    
    #[test]
    fn test_expired_nodes_detection() {
        let mut view = ClusterView::new();
        let mut node = create_test_node("test_node", 5001);
        
        // Set last_seen to past time
        node.last_seen = Instant::now() - Duration::from_secs(100);
        view.add_node(node);
        
        let failure_timeout = Duration::from_secs(60);
        let expired = view.check_expired_nodes(failure_timeout);
        
        // Node should be marked as failed
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], "test_node");
        assert_eq!(view.get_node("test_node").unwrap().status, NodeStatus::Failed);
    }
    
    #[test]
    fn test_cluster_health() {
        let mut view = ClusterView::new();
        
        // Empty cluster is healthy
        assert!(view.is_healthy());
        
        // Add 3 active nodes
        view.add_node(create_test_node("node1", 5001));
        view.add_node(create_test_node("node2", 5002));
        view.add_node(create_test_node("node3", 5003));
        assert!(view.is_healthy()); // 3/3 active
        
        // Mark one as failed
        view.mark_node_failed("node1");
        assert!(view.is_healthy()); // 2/3 active (majority)
        
        // Mark another as failed
        view.mark_node_failed("node2");
        assert!(!view.is_healthy()); // 1/3 active (minority)
    }
    
    #[test]
    fn test_preferred_node_selection() {
        let mut view = ClusterView::new();
        view.add_node(create_test_node("node1", 5001));
        view.add_node(create_test_node("node2", 5002));
        view.add_node(create_test_node("node3", 5003));
        
        // Same key should always return same node
        let node1 = view.get_preferred_node("test_key");
        let node2 = view.get_preferred_node("test_key");
        assert_eq!(node1.unwrap().node_id, node2.unwrap().node_id);
        
        // Different keys might return different nodes
        let node_a = view.get_preferred_node("key_a");
        let node_b = view.get_preferred_node("key_b");
        assert!(node_a.is_some());
        assert!(node_b.is_some());
    }
    
    #[test]
    fn test_cluster_stats() {
        let mut view = ClusterView::new();
        
        let mut node1 = create_test_node("node1", 5001);
        node1.load = 0.5;
        node1.memory_usage = 0.6;
        node1.cache_size = 1000;
        
        let mut node2 = create_test_node("node2", 5002);
        node2.load = 0.3;
        node2.memory_usage = 0.4;
        node2.cache_size = 2000;
        
        view.add_node(node1);
        view.add_node(node2);
        
        let stats = view.stats();
        assert_eq!(stats.total_nodes, 2);
        assert_eq!(stats.active_nodes, 2);
        assert_eq!(stats.total_cache_size, 3000);
        assert_eq!(stats.avg_load, 0.4);
        assert_eq!(stats.avg_memory_usage, 0.5);
    }
}