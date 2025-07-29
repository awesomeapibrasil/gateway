use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::acme::AcmeClient;
use crate::certificate::{Certificate, CertificateStore};
use crate::config::SslConfig;
use crate::error::{Result, SslError};
use crate::storage::{CertificateStorage, DatabaseStorage, VaultStorage};
use crate::watcher::CertificateWatcher;
use gateway_database::DatabaseManager;

/// SSL Manager - coordinates all SSL/TLS functionality
#[derive(Clone)]
pub struct SslManager {
    config: SslConfig,
    store: Arc<CertificateStore>,
    storage: Arc<dyn CertificateStorage>,
    acme_client: Arc<RwLock<Option<AcmeClient>>>,
    watcher: Arc<RwLock<Option<CertificateWatcher>>>,
}

impl SslManager {
    /// Create a new SSL manager
    pub async fn new(config: SslConfig) -> Result<Self> {
        info!("Creating SSL manager");

        let store = Arc::new(CertificateStore::new());

        // Initialize storage backend
        let storage: Arc<dyn CertificateStorage> = match config.certificate.storage_backend.as_str()
        {
            "database" => {
                info!("Using database storage for certificates");
                // This is a placeholder - in real implementation, you'd get the database from config
                let db_config = gateway_database::DatabaseConfig {
                    enabled: true,
                    backend: "sqlite".to_string(),
                    url: "sqlite::memory:".to_string(),
                    pool_size: 5,
                    timeout: std::time::Duration::from_secs(30),
                    migrations_path: "migrations".to_string(),
                    ssl_mode: "prefer".to_string(),
                };
                let database = DatabaseManager::new(&db_config).await.map_err(|e| {
                    SslError::StorageError(format!("Failed to initialize database: {e}"))
                })?;
                let db_storage = DatabaseStorage::new(database);
                db_storage.initialize().await?;
                Arc::new(db_storage)
            }
            "vault" => {
                info!("Using Vault storage for certificates");
                let vault_config = config.vault.as_ref().ok_or_else(|| {
                    SslError::ConfigError(
                        "Vault configuration required for vault storage".to_string(),
                    )
                })?;
                Arc::new(VaultStorage::new(vault_config.clone())?)
            }
            backend => {
                return Err(SslError::ConfigError(format!(
                    "Unsupported storage backend: {backend}"
                )));
            }
        };

        // Initialize ACME client if auto-SSL is enabled
        let acme_client = if config.auto_ssl.enabled {
            info!("Initializing ACME client");
            let mut client = AcmeClient::new(
                config.acme.directory_url.clone(),
                config.acme.contact_email.clone(),
            )?;
            client.initialize().await?;
            client
                .create_account(config.acme.terms_of_service_agreed)
                .await?;
            Some(client)
        } else {
            None
        };

        // Initialize certificate watcher
        let watcher = CertificateWatcher::new(
            config.certificate.clone(),
            Arc::clone(&store),
            Arc::clone(&storage),
        )?;

        Ok(Self {
            config,
            store,
            storage,
            acme_client: Arc::new(RwLock::new(acme_client)),
            watcher: Arc::new(RwLock::new(Some(watcher))),
        })
    }

    /// Initialize the SSL manager
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing SSL manager");

        // Load existing certificates from storage
        if let Some(mut watcher) = self.watcher.write().await.take() {
            watcher.load_certificates_from_storage().await?;

            // Start file watching if enabled
            if self.config.certificate.watch_external_updates {
                watcher.start_watching().await?;

                // Start renewal process
                watcher.start_renewal_process().await?;

                // For now, just store the watcher without background processing
                // In a real implementation, you'd handle the background tasks properly
                info!("Certificate watcher started");
            }

            *self.watcher.write().await = Some(watcher);
        }

        // Request certificates for configured domains if auto-SSL is enabled
        if self.config.auto_ssl.enabled && !self.config.auto_ssl.domains.is_empty() {
            self.provision_certificates().await?;
        }

        info!("SSL manager initialized successfully");
        Ok(())
    }

    /// Get a certificate for a domain
    pub async fn get_certificate(&self, domain: &str) -> Option<Certificate> {
        debug!("Getting certificate for domain: {}", domain);

        // First check in-memory store
        if let Some(cert) = self.store.get(domain) {
            if !cert.info.is_expired() {
                return Some(cert);
            } else {
                warn!("Certificate for domain {} is expired", domain);
                self.store.remove(domain);
            }
        }

        // If not in memory, try to load from storage
        match self.storage.get_certificate(domain).await {
            Ok(Some(cert_info)) => {
                if !cert_info.is_expired() {
                    match self.create_certificate_from_info(cert_info) {
                        Ok(certificate) => {
                            self.store.insert(domain, certificate.clone());
                            Some(certificate)
                        }
                        Err(e) => {
                            error!("Failed to create certificate for domain {}: {}", domain, e);
                            None
                        }
                    }
                } else {
                    warn!("Certificate for domain {} is expired in storage", domain);
                    None
                }
            }
            Ok(None) => {
                debug!("Certificate not found for domain: {}", domain);
                None
            }
            Err(e) => {
                error!("Failed to load certificate for domain {}: {}", domain, e);
                None
            }
        }
    }

    /// Request a new certificate for a domain
    pub async fn request_certificate(&self, domain: &str) -> Result<Certificate> {
        info!("Requesting new certificate for domain: {}", domain);

        let mut acme_client_guard = self.acme_client.write().await;
        let acme_client = acme_client_guard
            .as_mut()
            .ok_or_else(|| SslError::AcmeError("ACME client not initialized".to_string()))?;

        // Request certificate from ACME
        let cert_key_pair = acme_client
            .request_certificate(&[domain.to_string()])
            .await?;

        // Use the actual certificate and private key from ACME
        let certificate = Certificate::from_pem(
            domain.to_string(),
            &cert_key_pair.certificate,
            &cert_key_pair.private_key,
            None,
        )?;

        // Store the certificate
        self.store.insert(domain, certificate.clone());
        self.storage
            .store_certificate(domain, &certificate.info)
            .await?;

        info!(
            "Certificate provisioned successfully for domain: {}",
            domain
        );
        Ok(certificate)
    }

    /// Provision certificates for all configured domains
    async fn provision_certificates(&self) -> Result<()> {
        info!("Provisioning certificates for configured domains");

        for domain in &self.config.auto_ssl.domains {
            // Check if we already have a valid certificate
            if let Some(cert) = self.store.get(domain) {
                if !cert
                    .info
                    .needs_renewal(self.config.auto_ssl.renewal_threshold_days)
                {
                    debug!("Certificate for domain {} is still valid", domain);
                    continue;
                }
            }

            // Request new certificate
            match self.request_certificate(domain).await {
                Ok(_) => {
                    info!(
                        "Successfully provisioned certificate for domain: {}",
                        domain
                    );
                }
                Err(e) => {
                    error!(
                        "Failed to provision certificate for domain {}: {}",
                        domain, e
                    );
                }
            }
        }

        Ok(())
    }

    /// Install a certificate manually
    pub async fn install_certificate(
        &self,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
        chain_pem: Option<&str>,
    ) -> Result<()> {
        info!("Installing certificate manually for domain: {}", domain);

        let certificate = Certificate::from_pem(domain.to_string(), cert_pem, key_pem, chain_pem)?;

        // Store the certificate
        self.store.insert(domain, certificate.clone());
        self.storage
            .store_certificate(domain, &certificate.info)
            .await?;

        info!("Certificate installed successfully for domain: {}", domain);
        Ok(())
    }

    /// Remove a certificate
    pub async fn remove_certificate(&self, domain: &str) -> Result<()> {
        info!("Removing certificate for domain: {}", domain);

        self.store.remove(domain);
        self.storage.delete_certificate(domain).await?;

        info!("Certificate removed successfully for domain: {}", domain);
        Ok(())
    }

    /// List all certificates
    pub fn list_certificates(&self) -> Vec<String> {
        self.store.domains()
    }

    /// Get certificate information
    pub fn get_certificate_info(
        &self,
        domain: &str,
    ) -> Option<crate::certificate::CertificateInfo> {
        self.store.get(domain).map(|cert| cert.info)
    }

    /// Check certificate status
    pub fn check_certificate_status(&self, domain: &str) -> Option<CertificateStatus> {
        self.store.get(domain).map(|cert| {
            if cert.info.is_expired() {
                CertificateStatus::Expired
            } else if cert
                .info
                .needs_renewal(self.config.auto_ssl.renewal_threshold_days)
            {
                CertificateStatus::NeedsRenewal
            } else {
                CertificateStatus::Valid
            }
        })
    }

    /// Get the certificate store
    pub fn get_store(&self) -> Arc<CertificateStore> {
        Arc::clone(&self.store)
    }

    /// Create Certificate object from CertificateInfo
    fn create_certificate_from_info(
        &self,
        cert_info: crate::certificate::CertificateInfo,
    ) -> Result<Certificate> {
        // Convert DER bytes back to PEM for Certificate::from_pem
        let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", cert_info.certificate.clone()));

        let key_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", cert_info.private_key.clone()));

        let chain_pem = cert_info
            .certificate_chain
            .as_ref()
            .map(|chain| pem::encode(&pem::Pem::new("CERTIFICATE", chain.clone())));

        Certificate::from_pem(
            cert_info.domain.clone(),
            &cert_pem,
            &key_pem,
            chain_pem.as_deref(),
        )
    }
}

/// Certificate status
#[derive(Debug, Clone, PartialEq)]
pub enum CertificateStatus {
    Valid,
    NeedsRenewal,
    Expired,
}
