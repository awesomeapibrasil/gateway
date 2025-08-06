use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::ptr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// A segmented LRU cache that reduces contention by partitioning keys across multiple segments
pub struct SegmentedLRU<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    segments: Vec<Arc<Mutex<LRUSegment<K, V>>>>,
    segment_count: usize,
    max_size_per_segment: usize,
}

/// Internal LRU segment implementation
pub struct LRUSegment<K, V> {
    map: HashMap<K, Box<LRUNode<K, V>>>,
    head: *mut LRUNode<K, V>,
    tail: *mut LRUNode<K, V>,
    size: usize,
    max_size: usize,
}

/// LRU node with intrusive linked list pointers
pub struct LRUNode<K, V> {
    key: K,
    value: V,
    prev: *mut LRUNode<K, V>,
    next: *mut LRUNode<K, V>,
    access_time: Instant,
    access_count: u64,
}

impl<K, V> SegmentedLRU<K, V>
where
    K: Hash + Eq + Clone + Default,
    V: Clone + Default,
{
    /// Create a new segmented LRU cache
    pub fn new(segment_count: usize, total_capacity: usize) -> Self {
        let segment_count = segment_count.max(1);
        let max_size_per_segment = total_capacity / segment_count;

        let mut segments = Vec::with_capacity(segment_count);
        for _ in 0..segment_count {
            segments.push(Arc::new(Mutex::new(LRUSegment::new(max_size_per_segment))));
        }

        Self {
            segments,
            segment_count,
            max_size_per_segment,
        }
    }

    /// Get the segment index for a given key
    fn get_segment_index(&self, key: &K) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.segment_count
    }

    /// Get a value from the cache
    pub fn get(&self, key: &K) -> Option<V> {
        let segment_idx = self.get_segment_index(key);
        let segment = &self.segments[segment_idx];
        let mut segment_guard = segment.lock().unwrap();
        segment_guard.get(key)
    }

    /// Insert a value into the cache
    pub fn insert(&self, key: K, value: V) -> Option<V> {
        let segment_idx = self.get_segment_index(&key);
        let segment = &self.segments[segment_idx];
        let mut segment_guard = segment.lock().unwrap();
        segment_guard.insert(key, value)
    }

    /// Remove a value from the cache
    pub fn remove(&self, key: &K) -> Option<V> {
        let segment_idx = self.get_segment_index(key);
        let segment = &self.segments[segment_idx];
        let mut segment_guard = segment.lock().unwrap();
        segment_guard.remove(key)
    }

    /// Get the current size of the cache
    pub fn len(&self) -> usize {
        self.segments
            .iter()
            .map(|segment| segment.lock().unwrap().len())
            .sum()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all segments
    pub fn clear(&self) {
        for segment in &self.segments {
            segment.lock().unwrap().clear();
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> SegmentedLRUStats {
        let mut total_size = 0;
        let mut total_access_count = 0;
        let mut segment_stats = Vec::new();

        for segment in &self.segments {
            let segment_guard = segment.lock().unwrap();
            let size = segment_guard.len();
            let access_count = segment_guard.total_access_count();

            total_size += size;
            total_access_count += access_count;
            segment_stats.push(SegmentStats { size, access_count });
        }

        SegmentedLRUStats {
            total_size,
            total_access_count,
            segment_count: self.segment_count,
            max_size_per_segment: self.max_size_per_segment,
            segment_stats,
        }
    }
}

impl<K, V> LRUSegment<K, V>
where
    K: Hash + Eq + Clone + Default,
    V: Clone + Default,
{
    /// Create a new LRU segment
    fn new(max_size: usize) -> Self
    where
        K: Default,
        V: Default,
    {
        let mut segment = Self {
            map: HashMap::new(),
            head: ptr::null_mut(),
            tail: ptr::null_mut(),
            size: 0,
            max_size,
        };

        // Create sentinel nodes with default values
        let head_node = Box::into_raw(Box::new(LRUNode {
            key: K::default(),
            value: V::default(),
            prev: ptr::null_mut(),
            next: ptr::null_mut(),
            access_time: Instant::now(),
            access_count: 0,
        }));

        let tail_node = Box::into_raw(Box::new(LRUNode {
            key: K::default(),
            value: V::default(),
            prev: ptr::null_mut(),
            next: ptr::null_mut(),
            access_time: Instant::now(),
            access_count: 0,
        }));

        unsafe {
            (*head_node).next = tail_node;
            (*tail_node).prev = head_node;
        }

        segment.head = head_node;
        segment.tail = tail_node;

        segment
    }

    /// Get a value and move it to the front
    fn get(&mut self, key: &K) -> Option<V> {
        if let Some(node_ptr) = self.map.get(key) {
            let node_ptr = node_ptr.as_ref() as *const LRUNode<K, V> as *mut LRUNode<K, V>;
            unsafe {
                // Update access statistics
                (*node_ptr).access_time = Instant::now();
                (*node_ptr).access_count += 1;

                // Move to front
                self.move_to_front(node_ptr);

                Some((*node_ptr).value.clone())
            }
        } else {
            None
        }
    }

    /// Insert a new key-value pair
    fn insert(&mut self, key: K, value: V) -> Option<V> {
        if let Some(existing_node) = self.map.get(&key) {
            // Update existing node
            let node_ptr = existing_node.as_ref() as *const LRUNode<K, V> as *mut LRUNode<K, V>;
            unsafe {
                let old_value = (*node_ptr).value.clone();
                (*node_ptr).value = value;
                (*node_ptr).access_time = Instant::now();
                (*node_ptr).access_count += 1;
                self.move_to_front(node_ptr);
                Some(old_value)
            }
        } else {
            // Evict if necessary
            if self.size >= self.max_size {
                self.evict_lru();
            }

            // Create new node
            let new_node = Box::new(LRUNode {
                key: key.clone(),
                value,
                prev: ptr::null_mut(),
                next: ptr::null_mut(),
                access_time: Instant::now(),
                access_count: 1,
            });

            let node_ptr = Box::into_raw(new_node);
            self.map.insert(key, unsafe { Box::from_raw(node_ptr) });

            // Add to front
            unsafe {
                self.add_to_front(node_ptr);
            }

            self.size += 1;
            None
        }
    }

    /// Remove a key from the cache
    fn remove(&mut self, key: &K) -> Option<V> {
        if let Some(node_box) = self.map.remove(key) {
            let node_ptr = Box::into_raw(node_box);
            unsafe {
                let value = (*node_ptr).value.clone();
                self.remove_node(node_ptr);
                drop(Box::from_raw(node_ptr)); // Clean up the node
                self.size -= 1;
                Some(value)
            }
        } else {
            None
        }
    }

    /// Get the current size of the segment
    fn len(&self) -> usize {
        self.size
    }

    /// Clear all nodes from the segment
    fn clear(&mut self)
    where
        K: Hash + Eq + Clone,
        V: Clone,
    {
        // Remove all nodes
        let keys: Vec<K> = self.map.keys().cloned().collect();
        for key in keys {
            self.remove(&key);
        }
    }

    /// Get total access count for all nodes
    fn total_access_count(&self) -> u64 {
        self.map.values().map(|node| node.access_count).sum()
    }

    /// Move a node to the front of the list (most recently used)
    unsafe fn move_to_front(&mut self, node: *mut LRUNode<K, V>) {
        self.remove_node(node);
        self.add_to_front(node);
    }

    /// Add a node to the front of the list
    unsafe fn add_to_front(&mut self, node: *mut LRUNode<K, V>) {
        let first_node = (*self.head).next;

        (*node).next = first_node;
        (*node).prev = self.head;
        (*first_node).prev = node;
        (*self.head).next = node;
    }

    /// Remove a node from the linked list
    unsafe fn remove_node(&mut self, node: *mut LRUNode<K, V>) {
        let prev_node = (*node).prev;
        let next_node = (*node).next;

        (*prev_node).next = next_node;
        (*next_node).prev = prev_node;
    }

    /// Evict the least recently used node
    fn evict_lru(&mut self) {
        unsafe {
            let lru_node = (*self.tail).prev;
            if lru_node != self.head {
                let key = (*lru_node).key.clone();
                self.remove(&key);
            }
        }
    }
}

// Implement Drop for proper cleanup
// Implement Drop without trait bounds since we handle cleanup manually
impl<K, V> Drop for LRUSegment<K, V> {
    fn drop(&mut self) {
        // Manually clear the map
        self.map.clear();
        self.size = 0;

        // Clean up sentinel nodes
        if !self.head.is_null() {
            unsafe {
                drop(Box::from_raw(self.head));
            }
        }
        if !self.tail.is_null() {
            unsafe {
                drop(Box::from_raw(self.tail));
            }
        }
    }
}

// Safe to send between threads
unsafe impl<K: Send, V: Send> Send for SegmentedLRU<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
}

unsafe impl<K: Sync, V: Sync> Sync for SegmentedLRU<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
}

/// Statistics for the segmented LRU cache
#[derive(Debug, Clone)]
pub struct SegmentedLRUStats {
    pub total_size: usize,
    pub total_access_count: u64,
    pub segment_count: usize,
    pub max_size_per_segment: usize,
    pub segment_stats: Vec<SegmentStats>,
}

/// Statistics for an individual segment
#[derive(Debug, Clone)]
pub struct SegmentStats {
    pub size: usize,
    pub access_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_basic_operations() {
        let cache = SegmentedLRU::new(4, 10);

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
    fn test_lru_eviction() {
        let cache = SegmentedLRU::new(1, 2); // Single segment, capacity 2

        cache.insert(1, "one");
        cache.insert(2, "two");
        cache.insert(3, "three"); // Should evict 1

        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&2), Some("two"));
        assert_eq!(cache.get(&3), Some("three"));
    }

    #[test]
    fn test_concurrent_access() {
        let cache = Arc::new(SegmentedLRU::new(8, 100));
        let mut handles = vec![];

        // Spawn multiple threads doing concurrent operations
        for i in 0..10 {
            let cache_clone = Arc::clone(&cache);
            let handle = thread::spawn(move || {
                for j in 0..100 {
                    let key = format!("key_{}_{}", i, j);
                    let value = format!("value_{}_{}", i, j);
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

        // Cache should have at most 100 items
        assert!(cache.len() <= 100);
    }

    #[test]
    fn test_stats() {
        let cache = SegmentedLRU::new(2, 10);

        cache.insert("a", 1);
        cache.insert("b", 2);
        cache.get(&"a");
        cache.get(&"b");
        cache.get(&"a");

        let stats = cache.stats();
        assert_eq!(stats.total_size, 2);
        assert_eq!(stats.segment_count, 2);
        assert!(stats.total_access_count >= 3); // At least 3 accesses
    }
}
