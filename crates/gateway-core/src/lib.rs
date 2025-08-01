//! Gateway Core Library
//!
//! This is the main library for the Pingora-based API Gateway, providing
//! core functionality including proxy services, load balancing, and integration
//! with WAF, caching, database, and monitoring components.
//!
//! # Pingora Integration
//!
//! This library now includes direct integration with Cloudflare's Pingora framework
//! for high-performance networking. The `pingora_adapter` module provides the basic
//! integration skeleton and can be extended for full production use.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use gateway_core::pingora_adapter::PingoraGateway;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let gateway = PingoraGateway::new("MyGateway")?;
//!     gateway.run_forever();
//!     Ok(())
//! }
//! ```
//!
//! ## Integration Status
//!
//! - ✅ Basic Pingora server initialization
//! - ✅ Configuration structure foundation
//! - 🚧 HTTP service integration (planned)
//! - 🚧 Proxy service integration (planned)
//! - 🚧 WAF processing integration (planned)
//! - 🚧 Load balancing integration (planned)
//! - 🚧 SSL/TLS integration (planned)
//! - 🚧 Monitoring integration (planned)

#![allow(clippy::uninlined_format_args)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::match_ref_pats)]

pub mod config;
pub mod error;
pub mod gateway;
pub mod ingress;
pub mod pingora_adapter;
pub mod pingora_config;
pub mod pingora_proxy;
pub mod pingora_service;
pub mod pingora_ssl;
pub mod proxy;
pub mod server;
pub mod types;

pub use config::GatewayConfig;
pub use error::{GatewayError, Result};
pub use gateway::Gateway;
pub use ingress::IngressController;
pub use pingora_adapter::PingoraGateway;
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
