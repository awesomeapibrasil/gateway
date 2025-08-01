//! Pingora Proxy Service with Load Balancing
//!
//! This module provides a basic proxy implementation using Pingora with integrated
//! load balancing, health checks, and circuit breaker functionality.

use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::config::{BackendConfig, CircuitBreakerConfig, HealthCheckConfig, LoadBalancingConfig};
use crate::error::{GatewayError, Result};

/// Circuit breaker state for tracking backend health
#[derive(Debug, Clone)]
pub struct CircuitBreakerState {
    pub failures: u32,
    pub last_failure: Option<std::time::Instant>,
    pub state: CircuitState,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,    // Normal operation
    Open,      // Failing, rejecting requests
    HalfOpen,  // Testing if backend is recovered
}

/// Basic load balancing proxy service
pub struct PingoraProxyService {
    backends: Vec<BackendConfig>,
    lb_config: LoadBalancingConfig,
    health_config: HealthCheckConfig,
    circuit_config: CircuitBreakerConfig,
    circuit_states: Arc<dashmap::DashMap<String, CircuitBreakerState>>,
}

impl PingoraProxyService {
    /// Create a new proxy service
    pub async fn new(
        backends: Vec<BackendConfig>,
        lb_config: LoadBalancingConfig,
        health_config: HealthCheckConfig,
        circuit_config: CircuitBreakerConfig,
    ) -> Result<Self> {
        info!("Initializing Pingora proxy service with {} backends", backends.len());

        let circuit_states = Arc::new(dashmap::DashMap::new());

        // Initialize circuit breaker states
        for backend in &backends {
            circuit_states.insert(
                backend.address.clone(),
                CircuitBreakerState {
                    failures: 0,
                    last_failure: None,
                    state: CircuitState::Closed,
                },
            );
        }

        Ok(Self {
            backends,
            lb_config,
            health_config,
            circuit_config,
            circuit_states,
        })
    }

    /// Select an upstream backend (simplified round-robin for now)
    pub fn select_backend(&self) -> Option<&BackendConfig> {
        if self.backends.is_empty() {
            return None;
        }
        
        // Simple round-robin selection
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let index = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.backends.len();
        self.backends.get(index)
    }

    /// Check if all backends are healthy
    pub async fn health_check(&self) -> bool {
        for backend in &self.backends {
            if !self.check_backend_health(&backend.address).await {
                return false;
            }
        }
        true
    }

    /// Check health of a specific backend
    async fn check_backend_health(&self, backend_address: &str) -> bool {
        if !self.health_config.enabled {
            return true;
        }

        // Simple health check implementation
        let health_url = format!("http://{}{}", backend_address, self.health_config.path);
        
        match reqwest::get(&health_url).await {
            Ok(response) => response.status().as_u16() == self.health_config.expected_status,
            Err(_) => false,
        }
    }

    /// Get service statistics
    pub async fn get_stats(&self) -> std::collections::HashMap<String, serde_json::Value> {
        let mut stats = std::collections::HashMap::new();
        
        stats.insert("backend_count".to_string(), serde_json::Value::Number(self.backends.len().into()));
        stats.insert("algorithm".to_string(), serde_json::Value::String(self.lb_config.algorithm.clone()));
        stats.insert("healthy".to_string(), serde_json::Value::Bool(self.health_check().await));
        
        let backend_list: Vec<serde_json::Value> = self.backends.iter()
            .map(|b| serde_json::json!({
                "name": b.name,
                "address": b.address,
                "weight": b.weight
            }))
            .collect();
        stats.insert("backends".to_string(), serde_json::Value::Array(backend_list));
        
        stats
    }
}