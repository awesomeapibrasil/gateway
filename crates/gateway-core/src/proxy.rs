use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::config::UpstreamConfig;
use crate::error::{GatewayError, Result};
use crate::types::{Backend, RequestMetadata, ResponseMetadata};

use gateway_auth::AuthManager;
use gateway_cache::CacheManager;
use gateway_monitoring::MonitoringManager;
use gateway_plugins::PluginManager;
use gateway_waf::{RequestContext, WafEngine};

/// Gateway proxy that handles request routing and processing
#[allow(dead_code)]
pub struct GatewayProxy {
    config: UpstreamConfig,
    waf: Arc<WafEngine>,
    cache: Arc<CacheManager>,
    auth: Arc<AuthManager>,
    monitoring: Arc<MonitoringManager>,
    plugins: Arc<PluginManager>,
    backends: Vec<Backend>,
}

impl GatewayProxy {
    /// Create a new Gateway proxy
    pub async fn new(
        config: &UpstreamConfig,
        waf: Arc<WafEngine>,
        cache: Arc<CacheManager>,
        auth: Arc<AuthManager>,
        monitoring: Arc<MonitoringManager>,
        plugins: Arc<PluginManager>,
    ) -> Result<Self> {
        info!(
            "Initializing Gateway proxy with {} backends",
            config.backends.len()
        );

        // Convert backend configs to runtime backends
        let backends = config
            .backends
            .iter()
            .map(|backend_config| Backend {
                name: backend_config.name.clone(),
                address: backend_config.address.clone(),
                weight: backend_config.weight,
                healthy: true,
                last_health_check: std::time::SystemTime::now(),
                active_connections: 0,
                total_requests: 0,
                failed_requests: 0,
                average_response_time: backend_config.timeout,
            })
            .collect();

        Ok(Self {
            config: config.clone(),
            waf,
            cache,
            auth,
            monitoring,
            plugins,
            backends,
        })
    }

    /// Process an incoming request
    pub async fn process_request(&self, request: RequestMetadata) -> Result<ResponseMetadata> {
        debug!("Processing request: {} {}", request.method, request.uri);

        // Convert RequestMetadata to RequestContext for WAF
        let waf_request = RequestContext {
            method: request.method.to_string(),
            uri: request.uri.clone(),
            headers: request.headers.clone(),
            query_params: request.query_params.clone(),
            client_ip: request.client_ip,
            user_agent: request.user_agent.clone(),
            content_type: request.content_type.clone(),
            content_length: request.content_length,
            body: None, // Body not available in this context
        };

        // 1. WAF Evaluation
        let waf_result = match self.waf.evaluate_request(&waf_request).await {
            Ok(result) => result,
            Err(e) => {
                error!("WAF evaluation failed: {}", e);
                return Err(GatewayError::WafError(format!(
                    "WAF evaluation failed: {}",
                    e
                )));
            }
        };

        match waf_result {
            gateway_waf::WafResult::Block(reason) => {
                warn!("Request blocked by WAF: {}", reason);
                return Ok(ResponseMetadata {
                    status_code: 403,
                    headers: std::collections::HashMap::new(),
                    content_length: Some(0),
                    processing_time: std::time::Duration::from_millis(1),
                    backend_time: None,
                    cache_hit: false,
                    error: Some(reason),
                });
            }
            gateway_waf::WafResult::RateLimit(reason) => {
                warn!("Request rate limited: {}", reason);
                return Ok(ResponseMetadata {
                    status_code: 429,
                    headers: std::collections::HashMap::new(),
                    content_length: Some(0),
                    processing_time: std::time::Duration::from_millis(1),
                    backend_time: None,
                    cache_hit: false,
                    error: Some(reason),
                });
            }
            gateway_waf::WafResult::Allow | gateway_waf::WafResult::Log(_) => {
                // Continue processing
            }
        }

        // 2. Authentication (if enabled)
        if self.auth.is_enabled() && !self.is_public_path(&request.uri) {
            match self.auth.authenticate_request(&request.uri).await {
                Ok(_auth_context) => {
                    debug!("Request authenticated successfully");
                }
                Err(e) => {
                    warn!("Authentication failed: {}", e);
                    return Ok(ResponseMetadata {
                        status_code: 401,
                        headers: std::collections::HashMap::new(),
                        content_length: Some(0),
                        processing_time: std::time::Duration::from_millis(1),
                        backend_time: None,
                        cache_hit: false,
                        error: Some("Authentication failed".to_string()),
                    });
                }
            }
        }

        // 3. Cache Lookup
        if self.cache.is_enabled() {
            if let Ok(Some(_cached_data)) = self.cache.get(&request.uri).await {
                debug!("Cache hit for request: {}", request.uri);
                return Ok(ResponseMetadata {
                    status_code: 200,
                    headers: std::collections::HashMap::new(),
                    content_length: Some(1024), // placeholder
                    processing_time: std::time::Duration::from_millis(1),
                    backend_time: None,
                    cache_hit: true,
                    error: None,
                });
            }
        }

        // 4. Load Balancing and Backend Selection
        let backend = match self.select_backend().await {
            Some(backend) => backend,
            None => {
                error!("No healthy backends available");
                return Ok(ResponseMetadata {
                    status_code: 503,
                    headers: std::collections::HashMap::new(),
                    content_length: Some(0),
                    processing_time: std::time::Duration::from_millis(1),
                    backend_time: None,
                    cache_hit: false,
                    error: Some("No healthy backends".to_string()),
                });
            }
        };

        // 5. Forward Request to Backend
        let backend_start = std::time::Instant::now();
        let response = match self.forward_to_backend(&request, &backend).await {
            Ok(response) => response,
            Err(e) => {
                error!("Backend request failed: {}", e);
                return Ok(ResponseMetadata {
                    status_code: 502,
                    headers: std::collections::HashMap::new(),
                    content_length: Some(0),
                    processing_time: std::time::Duration::from_millis(1),
                    backend_time: Some(backend_start.elapsed()),
                    cache_hit: false,
                    error: Some("Backend error".to_string()),
                });
            }
        };

        let backend_time = backend_start.elapsed();

        // 6. Cache Response (if cacheable)
        if self.cache.is_enabled() && response.status_code == 200 {
            if let Err(e) = self.cache.set(&request.uri, &[]).await {
                warn!("Failed to cache response: {}", e);
            }
        }

        Ok(ResponseMetadata {
            status_code: response.status_code,
            headers: response.headers,
            content_length: response.content_length,
            processing_time: backend_start.elapsed(),
            backend_time: Some(backend_time),
            cache_hit: false,
            error: response.error,
        })
    }

    /// Select a backend using the configured load balancing algorithm
    async fn select_backend(&self) -> Option<Backend> {
        let healthy_backends: Vec<&Backend> = self.backends.iter().filter(|b| b.healthy).collect();

        if healthy_backends.is_empty() {
            return None;
        }

        match self.config.load_balancing.algorithm.as_str() {
            "round_robin" => {
                // Simple round-robin selection
                // In a real implementation, this would use atomic counters
                healthy_backends.first().cloned().cloned()
            }
            "least_connections" => {
                // Select backend with least active connections
                healthy_backends
                    .iter()
                    .min_by_key(|b| b.active_connections)
                    .map(|&b| b.clone())
            }
            "weighted" => {
                // Weighted selection based on backend weights
                // For now, just select the first one
                healthy_backends.first().cloned().cloned()
            }
            _ => {
                // Default to round-robin
                healthy_backends.first().cloned().cloned()
            }
        }
    }

    /// Forward request to the selected backend
    async fn forward_to_backend(
        &self,
        _request: &RequestMetadata,
        backend: &Backend,
    ) -> Result<ResponseMetadata> {
        debug!("Forwarding request to backend: {}", backend.name);

        // In a real implementation, this would use Pingora's proxy capabilities
        // to forward the request to the backend and return the response

        // For now, simulate a successful response
        Ok(ResponseMetadata {
            status_code: 200,
            headers: std::collections::HashMap::new(),
            content_length: Some(1024),
            processing_time: std::time::Duration::from_millis(100),
            backend_time: Some(std::time::Duration::from_millis(80)),
            cache_hit: false,
            error: None,
        })
    }

    /// Check if a path is in the public paths list
    fn is_public_path(&self, path: &str) -> bool {
        self.auth
            .get_public_paths()
            .iter()
            .any(|public_path| path.starts_with(public_path))
    }

    /// Update proxy configuration
    pub async fn update_config(&self, _config: &UpstreamConfig) -> Result<()> {
        info!("Updating proxy configuration");
        // In a real implementation, this would update the backend list,
        // load balancing configuration, health checks, etc.
        Ok(())
    }

    /// Check if the proxy is healthy
    pub async fn is_healthy(&self) -> bool {
        // Check if at least one backend is healthy
        self.backends.iter().any(|b| b.healthy)
    }
}
