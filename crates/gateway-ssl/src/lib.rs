//! Gateway SSL/TLS Management Library
//!
//! This library provides auto-SSL functionality similar to Caddy Server, including:
//! - ACME (Let's Encrypt) certificate provisioning and renewal
//! - Certificate storage in Vault or database
//! - In-memory certificate management with automatic updates
//! - Dynamic certificate loading for ingress

pub mod acme;
pub mod certificate;
pub mod config;
pub mod error;
pub mod manager;
pub mod storage;
pub mod watcher;

pub use certificate::{Certificate, CertificateInfo, CertificateStore};
pub use config::{SslConfig, AcmeConfig, VaultConfig, CertificateConfig};
pub use error::{SslError, Result};
pub use manager::SslManager;
pub use storage::{CertificateStorage, DatabaseStorage, VaultStorage};
pub use watcher::CertificateWatcher;

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Global SSL manager instance
static SSL_MANAGER: once_cell::sync::Lazy<Arc<RwLock<Option<SslManager>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(None)));

/// Initialize the SSL manager with the given configuration
pub async fn init_ssl_manager(config: SslConfig) -> Result<()> {
    info!("Initializing SSL manager");
    
    let manager = SslManager::new(config).await?;
    
    let mut instance = SSL_MANAGER.write().await;
    *instance = Some(manager);
    
    info!("SSL manager initialized successfully");
    Ok(())
}

/// Get a reference to the global SSL manager instance
pub async fn get_ssl_manager() -> Option<SslManager> {
    SSL_MANAGER.read().await.clone()
}