//! Pingora SSL/TLS Termination
//!
//! This module provides SSL/TLS termination capabilities using Pingora with
//! integration to the gateway's certificate management system.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::error::{GatewayError, Result};
use gateway_ssl::SslManager;

/// SSL/TLS configuration for Pingora
pub struct PingoraSslConfig {
    pub ssl_manager: Arc<SslManager>,
    pub certificate_paths: Arc<RwLock<HashMap<String, CertificatePaths>>>,
    pub default_cert_path: String,
    pub default_key_path: String,
    pub require_client_cert: bool,
    pub client_ca_path: Option<String>,
    pub protocols: Vec<String>,
    pub ciphers: Option<String>,
    pub prefer_server_ciphers: bool,
}

#[derive(Debug, Clone)]
pub struct CertificatePaths {
    pub cert_path: String,
    pub key_path: String,
}

impl PingoraSslConfig {
    /// Create a new SSL configuration
    pub async fn new(
        ssl_manager: Arc<SslManager>,
        default_cert_path: String,
        default_key_path: String,
        require_client_cert: bool,
        client_ca_path: Option<String>,
    ) -> Result<Self> {
        info!("Initializing Pingora SSL configuration");

        let certificate_paths = Arc::new(RwLock::new(HashMap::new()));

        let config = Self {
            ssl_manager,
            certificate_paths,
            default_cert_path,
            default_key_path,
            require_client_cert,
            client_ca_path,
            protocols: vec!["TLSv1.2".to_string(), "TLSv1.3".to_string()],
            ciphers: Some(
                "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS".to_string(),
            ),
            prefer_server_ciphers: true,
        };

        // Validate default certificate files
        config.validate_certificate_files(&config.default_cert_path, &config.default_key_path)?;

        info!("Pingora SSL configuration initialized successfully");
        Ok(config)
    }

    /// Validate certificate and key files exist
    fn validate_certificate_files(&self, cert_path: &str, key_path: &str) -> Result<()> {
        if !Path::new(cert_path).exists() {
            return Err(GatewayError::SslError(format!(
                "Certificate file not found: {}",
                cert_path
            )));
        }

        if !Path::new(key_path).exists() {
            return Err(GatewayError::SslError(format!(
                "Private key file not found: {}",
                key_path
            )));
        }

        debug!(
            "Certificate files validated: {} and {}",
            cert_path, key_path
        );
        Ok(())
    }

    /// Get certificate paths for a specific domain
    pub async fn get_certificate_paths(&self, domain: &str) -> Result<CertificatePaths> {
        debug!("Getting certificate paths for domain: {}", domain);

        // Check if we have cached paths for this domain
        {
            let paths = self.certificate_paths.read().await;
            if let Some(cert_paths) = paths.get(domain) {
                debug!("Using cached certificate paths for domain: {}", domain);
                return Ok(cert_paths.clone());
            }
        }

        // Try to get certificate for domain from SSL manager
        match self.ssl_manager.get_certificate(domain).await {
            Some(_cert_info) => {
                debug!("Found certificate for domain: {}", domain);

                // Use the actual certificate paths from the SSL manager
                let cert_paths = CertificatePaths {
                    cert_path: format!("/etc/ssl/certs/gateway/{}.crt", domain),
                    key_path: format!("/etc/ssl/private/gateway/{}.key", domain),
                };

                // Cache the paths
                let mut paths = self.certificate_paths.write().await;
                paths.insert(domain.to_string(), cert_paths.clone());

                Ok(cert_paths)
            }
            None => {
                debug!("No certificate found for domain: {}, using default", domain);
                self.get_default_certificate_paths().await
            }
        }
    }

    /// Get default certificate paths
    async fn get_default_certificate_paths(&self) -> Result<CertificatePaths> {
        Ok(CertificatePaths {
            cert_path: self.default_cert_path.clone(),
            key_path: self.default_key_path.clone(),
        })
    }

    /// Reload certificates for all domains
    pub async fn reload_certificates(&self) -> Result<()> {
        info!("Reloading SSL certificates");

        let domains: Vec<String> = {
            let paths = self.certificate_paths.read().await;
            paths.keys().filter(|k| *k != "default").cloned().collect()
        };

        for domain in &domains {
            if let Err(e) = self.refresh_domain_certificate(domain).await {
                error!("Failed to refresh certificate for domain {}: {}", domain, e);
            }
        }

        info!("SSL certificate reload completed");
        Ok(())
    }

    /// Refresh certificate for a specific domain
    async fn refresh_domain_certificate(&self, domain: &str) -> Result<()> {
        debug!("Refreshing certificate for domain: {}", domain);

        // Remove cached paths
        {
            let mut paths = self.certificate_paths.write().await;
            paths.remove(domain);
        }

        // Trigger certificate request if needed
        if let Err(e) = self.ssl_manager.request_certificate(domain).await {
            warn!("Failed to request certificate for domain {}: {}", domain, e);
        }

        // Get new certificate paths
        self.get_certificate_paths(domain).await?;

        debug!("Certificate refreshed for domain: {}", domain);
        Ok(())
    }

    /// Add a new domain for SSL termination
    pub async fn add_domain(&self, domain: &str) -> Result<()> {
        info!("Adding SSL support for domain: {}", domain);

        // Request certificate
        self.ssl_manager
            .request_certificate(domain)
            .await
            .map_err(|e| {
                GatewayError::SslError(format!(
                    "Failed to request certificate for {}: {}",
                    domain, e
                ))
            })?;

        // Get certificate paths (this will cache them)
        self.get_certificate_paths(domain).await?;

        info!("SSL support added for domain: {}", domain);
        Ok(())
    }

    /// Remove a domain from SSL termination
    pub async fn remove_domain(&self, domain: &str) -> Result<()> {
        info!("Removing SSL support for domain: {}", domain);

        let mut paths = self.certificate_paths.write().await;
        paths.remove(domain);

        info!("SSL support removed for domain: {}", domain);
        Ok(())
    }

    /// Get SSL statistics
    pub async fn get_ssl_stats(&self) -> HashMap<String, serde_json::Value> {
        let paths = self.certificate_paths.read().await;
        let mut stats = HashMap::new();

        stats.insert(
            "total_domains".to_string(),
            serde_json::Value::Number(paths.len().into()),
        );
        stats.insert(
            "protocols".to_string(),
            serde_json::Value::Array(
                self.protocols
                    .iter()
                    .map(|p| serde_json::Value::String(p.clone()))
                    .collect(),
            ),
        );
        stats.insert(
            "require_client_cert".to_string(),
            serde_json::Value::Bool(self.require_client_cert),
        );

        // Add domain list
        let domains: Vec<serde_json::Value> = paths
            .keys()
            .map(|domain| serde_json::Value::String(domain.clone()))
            .collect();
        stats.insert("domains".to_string(), serde_json::Value::Array(domains));

        stats
    }

    /// Validate SSL configuration
    pub async fn validate_configuration(&self) -> Result<Vec<String>> {
        let mut issues = Vec::new();

        // Check default certificate
        if !Path::new(&self.default_cert_path).exists() {
            issues.push(format!(
                "Default certificate file not found: {}",
                self.default_cert_path
            ));
        }

        if !Path::new(&self.default_key_path).exists() {
            issues.push(format!(
                "Default private key file not found: {}",
                self.default_key_path
            ));
        }

        // Check client CA if required
        if self.require_client_cert {
            if let Some(ca_path) = &self.client_ca_path {
                if !Path::new(ca_path).exists() {
                    issues.push(format!("Client CA file not found: {}", ca_path));
                }
            } else {
                issues.push(
                    "Client certificate verification enabled but no CA file specified".to_string(),
                );
            }
        }

        // Validate protocol configuration
        if self.protocols.is_empty() {
            issues.push("No SSL/TLS protocols enabled".to_string());
        }

        if issues.is_empty() {
            info!("SSL configuration validation passed");
        } else {
            warn!("SSL configuration validation found {} issues", issues.len());
        }

        Ok(issues)
    }
}
