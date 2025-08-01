//! Pingora Adapter Module
//!
//! This module provides integration with Cloudflare's Pingora framework for high-performance
//! networking. It serves as the foundation for migrating the gateway's core networking stack
//! to leverage Pingora's optimized protocols and load balancing capabilities.
//!
//! # Architecture Integration Points
//!
//! The following areas are planned for future Pingora integration:
//! - HTTP/HTTPS proxy handlers
//! - Load balancing algorithms and health checks  
//! - TLS termination and upstream connections
//! - Request/response lifecycle management
//! - Metrics collection and observability hooks
//! - Connection pooling and keep-alive management

use pingora::server::Server;
use std::sync::Arc;
use tracing::info;

/// Basic Pingora server implementation for the Gateway
/// 
/// This struct demonstrates the minimal integration pattern for Pingora within
/// the existing gateway architecture. Future development should expand this to
/// integrate with the gateway's configuration system, WAF engine, and monitoring.
pub struct PingoraGateway {
    server: Server,
}

impl PingoraGateway {
    /// Create a new Pingora gateway instance
    /// 
    /// # Example Basic Usage
    /// 
    /// ```rust,no_run
    /// use gateway_core::pingora_adapter::PingoraGateway;
    /// 
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let gateway = PingoraGateway::new("Gateway")?;
    ///     gateway.run_forever().await;
    ///     Ok(())
    /// }
    /// ```
    pub fn new(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Initializing Pingora gateway: {}", name);
        
        // Create server instance - in production this should integrate with gateway's config system
        let mut server = Server::new(None)?;
        server.bootstrap();
        
        Ok(PingoraGateway { server })
    }

    /// Run the Pingora server
    /// 
    /// This will block the current thread. In production integration, this should
    /// be coordinated with the gateway's lifecycle management and graceful shutdown.
    pub fn run_forever(self) {
        info!("Starting Pingora gateway server");
        self.server.run_forever();
    }

    /// Get server configuration for inspection
    /// 
    /// Useful for debugging and integration with gateway's config validation
    pub fn get_configuration(&self) -> &Arc<pingora::server::configuration::ServerConf> {
        &self.server.configuration
    }
}

/// Example function to demonstrate basic Pingora server setup
/// 
/// This can be called from main.rs or used in integration tests.
/// Production deployment should integrate with the gateway's configuration system.
/// 
/// # Integration Notes
/// 
/// Future development should:
/// - Add HTTP service listeners with the gateway's routing logic
/// - Integrate WAF processing in the request pipeline  
/// - Implement load balancing with gateway's backend configuration
/// - Add SSL/TLS termination using gateway's certificate management
/// - Connect metrics collection to gateway's monitoring system
/// - Implement health checks for gateway's service discovery
pub fn run_example_server() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting example Pingora server");
    
    let gateway = PingoraGateway::new("ExampleGateway")?;
    
    info!("Pingora gateway configured. Server ready to accept services.");
    info!("To add HTTP services, implement the following integration points:");
    info!("- HTTP request handlers with WAF processing");
    info!("- Proxy services with load balancing");
    info!("- SSL/TLS termination and certificate management");
    info!("- Health check endpoints and monitoring integration");
    
    gateway.run_forever();
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pingora_gateway_creation() {
        // Basic smoke test to ensure Pingora integration compiles
        let result = PingoraGateway::new("TestGateway");
        assert!(result.is_ok(), "Should be able to create PingoraGateway instance");
    }

    #[test] 
    fn test_configuration_access() {
        let gateway = PingoraGateway::new("TestGateway").expect("Should create gateway");
        let _config = gateway.get_configuration();
        // Basic test to ensure configuration is accessible
    }
}