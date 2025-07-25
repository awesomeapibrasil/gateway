//! Gateway Core Library
//! 
//! This is the main library for the Pingora-based API Gateway, providing
//! core functionality including proxy services, load balancing, and integration
//! with WAF, caching, database, and monitoring components.

pub mod config;
pub mod error;
pub mod gateway;
pub mod proxy;
pub mod server;
pub mod types;

pub use config::GatewayConfig;
pub use error::{GatewayError, Result};
pub use gateway::Gateway;
pub use proxy::GatewayProxy;
pub use server::GatewayServer;

use once_cell::sync::Lazy;
use std::sync::Arc;
use tracing::info;

/// Global gateway instance
pub static GATEWAY_INSTANCE: Lazy<Arc<tokio::sync::RwLock<Option<Gateway>>>> =
    Lazy::new(|| Arc::new(tokio::sync::RwLock::new(None)));

/// Initialize the gateway with the given configuration
pub async fn init_gateway(config: GatewayConfig) -> Result<()> {
    info!("Initializing gateway core");
    
    let gateway = Gateway::new(config).await?;
    
    let mut instance = GATEWAY_INSTANCE.write().await;
    *instance = Some(gateway);
    
    info!("Gateway core initialized successfully");
    Ok(())
}

/// Get a reference to the global gateway instance
pub async fn get_gateway() -> Option<Gateway> {
    GATEWAY_INSTANCE.read().await.clone()
}