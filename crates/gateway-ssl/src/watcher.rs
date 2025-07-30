use notify::{Event, RecursiveMode, Result as NotifyResult, Watcher};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::certificate::{Certificate, CertificateStore};
use crate::config::CertificateConfig;
use crate::error::{Result, SslError};
use crate::storage::CertificateStorage;

/// Certificate file watcher for automatic updates
pub struct CertificateWatcher {
    config: CertificateConfig,
    store: Arc<CertificateStore>,
    storage: Arc<dyn CertificateStorage>,
    _watcher: Option<notify::RecommendedWatcher>,
    receiver: Option<mpsc::Receiver<notify::Result<Event>>>,
}

impl CertificateWatcher {
    /// Create a new certificate watcher
    pub fn new(
        config: CertificateConfig,
        store: Arc<CertificateStore>,
        storage: Arc<dyn CertificateStorage>,
    ) -> Result<Self> {
        Ok(Self {
            config,
            store,
            storage,
            _watcher: None,
            receiver: None,
        })
    }

    /// Start watching for certificate file changes
    pub async fn start_watching(&mut self) -> Result<()> {
        if !self.config.watch_external_updates {
            debug!("Certificate file watching is disabled");
            return Ok(());
        }

        info!("Starting certificate file watcher");

        let (tx, rx) = mpsc::channel(100);
        self.receiver = Some(rx);

        let mut watcher = notify::recommended_watcher(move |res: NotifyResult<Event>| {
            if let Err(e) = tx.blocking_send(res) {
                error!("Failed to send file watcher event: {}", e);
            }
        })
        .map_err(SslError::WatcherError)?;

        // Watch the certificate cache directory
        let cache_path = Path::new(&self.config.cache_directory);
        if cache_path.exists() {
            watcher
                .watch(cache_path, RecursiveMode::Recursive)
                .map_err(SslError::WatcherError)?;
            info!(
                "Watching certificate directory: {}",
                self.config.cache_directory
            );
        } else {
            warn!(
                "Certificate cache directory does not exist: {}",
                self.config.cache_directory
            );
        }

        self._watcher = Some(watcher);

        Ok(())
    }

    /// Process file system events
    pub async fn process_events(&mut self) -> Result<()> {
        if let Some(receiver) = self.receiver.take() {
            let mut recv = receiver;
            while let Some(event_result) = recv.recv().await {
                match event_result {
                    Ok(event) => {
                        if let Err(e) = self.handle_file_event(event).await {
                            error!("Failed to handle file event: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("File watcher error: {}", e);
                    }
                }
            }
            self.receiver = Some(recv);
        }
        Ok(())
    }

    /// Handle a file system event
    async fn handle_file_event(&self, event: Event) -> Result<()> {
        debug!("Processing file event: {:?}", event);

        match event.kind {
            notify::EventKind::Create(_) | notify::EventKind::Modify(_) => {
                for path in &event.paths {
                    if let Some(extension) = path.extension() {
                        if extension == "crt" || extension == "pem" || extension == "cert" {
                            if let Err(e) = self.reload_certificate_from_file(path).await {
                                error!(
                                    "Failed to reload certificate from {}: {}",
                                    path.display(),
                                    e
                                );
                            }
                        }
                    }
                }
            }
            notify::EventKind::Remove(_) => {
                for path in &event.paths {
                    if let Some(domain) = self.extract_domain_from_path(path) {
                        info!("Certificate file removed for domain: {}", domain);
                        self.store.remove(&domain);
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Reload a certificate from a file
    async fn reload_certificate_from_file(&self, path: &Path) -> Result<()> {
        let domain = self.extract_domain_from_path(path).ok_or_else(|| {
            SslError::CertificateError("Cannot extract domain from path".to_string())
        })?;

        info!(
            "Reloading certificate for domain: {} from file: {}",
            domain,
            path.display()
        );

        // Try to find corresponding key file
        let cert_content = std::fs::read_to_string(path).map_err(SslError::IoError)?;

        let key_path = path.with_extension("key");
        if !key_path.exists() {
            return Err(SslError::CertificateError(format!(
                "Private key file not found: {}",
                key_path.display()
            )));
        }

        let key_content = std::fs::read_to_string(&key_path).map_err(SslError::IoError)?;

        // Try to find certificate chain file
        let chain_path = path.with_extension("chain.pem");
        let chain_content = if chain_path.exists() {
            Some(std::fs::read_to_string(&chain_path).map_err(SslError::IoError)?)
        } else {
            None
        };

        // Create certificate from PEM data
        let certificate = Certificate::from_pem(
            domain.clone(),
            &cert_content,
            &key_content,
            chain_content.as_deref(),
        )?;

        // Update in-memory store
        self.store.insert(&domain, certificate.clone());

        // Update persistent storage if configured
        if let Err(e) = self
            .storage
            .update_certificate(&domain, &certificate.info)
            .await
        {
            warn!("Failed to update certificate in persistent storage: {}", e);
        }

        info!("Certificate reloaded successfully for domain: {}", domain);
        Ok(())
    }

    /// Extract domain name from file path
    fn extract_domain_from_path(&self, path: &Path) -> Option<String> {
        path.file_stem()
            .and_then(|name| name.to_str())
            .map(|name| {
                // Remove common suffixes
                if name.ends_with(".chain") {
                    name.strip_suffix(".chain").unwrap_or(name)
                } else {
                    name
                }
            })
            .map(|s| s.to_string())
    }

    /// Start the automatic renewal process
    pub async fn start_renewal_process(&self) -> Result<()> {
        if !self.config.auto_reload {
            debug!("Automatic certificate renewal is disabled");
            return Ok(());
        }

        info!("Starting certificate renewal process");

        let store = Arc::clone(&self.store);
        let storage = Arc::clone(&self.storage);
        let reload_interval = self.config.reload_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(reload_interval);

            loop {
                interval.tick().await;

                debug!("Checking for certificates needing renewal");

                // Check certificates in the store for renewal
                let domains_needing_renewal = store.certificates_needing_renewal(30); // 30 days threshold

                for domain in domains_needing_renewal {
                    info!("Certificate for domain {} needs renewal", domain);

                    // In a real implementation, you would trigger ACME renewal here
                    // For now, just log the domain that needs renewal
                    warn!(
                        "Certificate renewal not yet implemented for domain: {}",
                        domain
                    );
                }

                // Check for expired certificates and remove them
                let expired_domains = store.expired_certificates();
                for domain in expired_domains {
                    warn!("Removing expired certificate for domain: {}", domain);
                    store.remove(&domain);

                    if let Err(e) = storage.delete_certificate(&domain).await {
                        error!("Failed to delete expired certificate from storage: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Load certificates from storage into memory
    pub async fn load_certificates_from_storage(&self) -> Result<()> {
        info!("Loading certificates from storage into memory");

        let domains = self.storage.list_certificates().await?;

        for domain in domains {
            match self.storage.get_certificate(&domain).await {
                Ok(Some(cert_info)) => {
                    // Convert certificate info to Certificate object
                    match self.create_certificate_from_info(cert_info) {
                        Ok(certificate) => {
                            self.store.insert(&domain, certificate);
                            debug!("Loaded certificate for domain: {}", domain);
                        }
                        Err(e) => {
                            error!(
                                "Failed to create certificate object for domain {}: {}",
                                domain, e
                            );
                        }
                    }
                }
                Ok(None) => {
                    warn!("Certificate not found in storage for domain: {}", domain);
                }
                Err(e) => {
                    error!("Failed to load certificate for domain {}: {}", domain, e);
                }
            }
        }

        info!("Loaded {} certificates from storage", self.store.len());
        Ok(())
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
