use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::config::IngressConfig;
use crate::error::{GatewayError, Result};
use crate::ingress::{annotations::IngressAnnotations, resources::IngressResource};

/// Ingress controller for managing Kubernetes ingress resources
pub struct IngressController {
    config: IngressConfig,
    ingresses: Arc<RwLock<HashMap<String, IngressResource>>>,
    routes: Arc<RwLock<HashMap<String, RouteConfig>>>,
}

/// Route configuration derived from ingress
#[derive(Debug, Clone)]
pub struct RouteConfig {
    pub host: String,
    pub path: String,
    pub backend_service: String,
    pub backend_port: Option<u16>,
    pub annotations: IngressAnnotations,
    pub tls_enabled: bool,
    pub ingress_id: String,
}

impl IngressController {
    /// Create a new ingress controller
    pub fn new(config: IngressConfig) -> Self {
        Self {
            config,
            ingresses: Arc::new(RwLock::new(HashMap::new())),
            routes: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Initialize the ingress controller
    pub async fn initialize(&self) -> Result<()> {
        if !self.config.enabled {
            debug!("Ingress controller is disabled");
            return Ok();
        }
        
        info!("Initializing ingress controller");
        info!("Watching for ingress class: {}", self.config.ingress_class);
        
        if self.config.watch_all_namespaces {
            info!("Watching all namespaces");
        } else if let Some(namespace) = &self.config.namespace {
            info!("Watching namespace: {}", namespace);
        }
        
        // In a real implementation, you would set up Kubernetes API watches here
        self.start_kubernetes_watch().await?;
        
        Ok(())
    }
    
    /// Start watching Kubernetes API for ingress changes
    async fn start_kubernetes_watch(&self) -> Result<()> {
        info!("Starting Kubernetes API watch for ingress resources");
        
        // This is a placeholder for actual Kubernetes API integration
        // In a real implementation, you would use the kubernetes-rs crate
        // and set up watches for Ingress resources
        
        warn!("Kubernetes API integration not yet implemented - this is a placeholder");
        
        Ok(())
    }
    
    /// Handle ingress resource creation or update
    pub async fn handle_ingress_upsert(&self, ingress: IngressResource) -> Result<()> {
        let ingress_id = ingress.get_id();
        
        if !ingress.should_handle(&self.config.ingress_class) {
            debug!("Ignoring ingress {} - not for our class", ingress_id);
            return Ok();
        }
        
        info!("Handling ingress upsert: {}", ingress_id);
        
        // Parse annotations
        let annotations = IngressAnnotations::new(
            ingress.metadata.annotations.clone(),
            self.config.annotations.clone(),
        );
        
        // Generate routes from ingress rules
        let mut new_routes = HashMap::new();
        
        for rule in &ingress.spec.rules {
            let host = rule.host.as_deref().unwrap_or("*");
            
            if let Some(http) = &rule.http {
                for path in &http.paths {
                    if let Some((service_name, service_port)) = path.backend.get_service_info() {
                        let route_key = format!("{}:{}", host, path.path.as_deref().unwrap_or("/"));
                        let route = RouteConfig {
                            host: host.to_string(),
                            path: path.path.as_deref().unwrap_or("/").to_string(),
                            backend_service: service_name,
                            backend_port: service_port,
                            annotations: annotations.clone(),
                            tls_enabled: ingress.has_tls(),
                            ingress_id: ingress_id.clone(),
                        };
                        
                        new_routes.insert(route_key, route);
                    }
                }
            }
        }
        
        // Update routes
        {
            let mut routes = self.routes.write().await;
            
            // Remove old routes for this ingress
            routes.retain(|_, route| route.ingress_id != ingress_id);
            
            // Add new routes
            for (key, route) in new_routes {
                info!("Adding route: {} -> {}:{}", key, route.backend_service, route.backend_port.unwrap_or(80));
                routes.insert(key, route);
            }
        }
        
        // Store the ingress
        {
            let mut ingresses = self.ingresses.write().await;
            ingresses.insert(ingress_id, ingress);
        }
        
        Ok(())
    }
    
    /// Handle ingress resource deletion
    pub async fn handle_ingress_delete(&self, namespace: &str, name: &str) -> Result<()> {
        let ingress_id = format!("{}/{}", namespace, name);
        
        info!("Handling ingress delete: {}", ingress_id);
        
        // Remove routes for this ingress
        {
            let mut routes = self.routes.write().await;
            let removed_count = routes.len();
            routes.retain(|_, route| route.ingress_id != ingress_id);
            let new_count = routes.len();
            info!("Removed {} routes for ingress {}", removed_count - new_count, ingress_id);
        }
        
        // Remove the ingress
        {
            let mut ingresses = self.ingresses.write().await;
            ingresses.remove(&ingress_id);
        }
        
        Ok(())
    }
    
    /// Find a route for the given host and path
    pub async fn find_route(&self, host: &str, path: &str) -> Option<RouteConfig> {
        let routes = self.routes.read().await;
        
        // Try exact match first
        let exact_key = format!("{}:{}", host, path);
        if let Some(route) = routes.get(&exact_key) {
            return Some(route.clone());
        }
        
        // Try wildcard host
        let wildcard_key = format!("*:{}", path);
        if let Some(route) = routes.get(&wildcard_key) {
            return Some(route.clone());
        }
        
        // Find best prefix match
        let mut best_match: Option<&RouteConfig> = None;
        let mut best_match_length = 0;
        
        for route in routes.values() {
            if (route.host == host || route.host == "*") && path.starts_with(&route.path) {
                if route.path.len() > best_match_length {
                    best_match = Some(route);
                    best_match_length = route.path.len();
                }
            }
        }
        
        best_match.cloned()
    }
    
    /// Get all configured hosts that need TLS certificates
    pub async fn get_tls_hosts(&self) -> Vec<String> {
        let ingresses = self.ingresses.read().await;
        let mut hosts = Vec::new();
        
        for ingress in ingresses.values() {
            if ingress.has_tls() {
                hosts.extend(ingress.get_tls_hosts());
            }
        }
        
        hosts.sort();
        hosts.dedup();
        hosts
    }
    
    /// Get all routes
    pub async fn get_routes(&self) -> HashMap<String, RouteConfig> {
        self.routes.read().await.clone()
    }
    
    /// Get ingress by ID
    pub async fn get_ingress(&self, ingress_id: &str) -> Option<IngressResource> {
        self.ingresses.read().await.get(ingress_id).cloned()
    }
    
    /// List all managed ingresses
    pub async fn list_ingresses(&self) -> Vec<IngressResource> {
        self.ingresses.read().await.values().cloned().collect()
    }
    
    /// Check if controller is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
    
    /// Get ingress class name
    pub fn get_ingress_class(&self) -> &str {
        &self.config.ingress_class
    }
}