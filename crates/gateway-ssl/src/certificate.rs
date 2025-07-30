use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn};

use x509_parser::prelude::FromDer;

use crate::error::{Result, SslError};

/// Certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub domain: String,
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub certificate_chain: Option<Vec<u8>>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub issuer: String,
    pub serial_number: String,
    pub fingerprint: String,
}

/// Certificate data structure
#[derive(Debug)]
pub struct Certificate {
    pub info: CertificateInfo,
    pub rustls_certificate: Option<rustls::pki_types::CertificateDer<'static>>,
    pub rustls_private_key: Option<rustls::pki_types::PrivateKeyDer<'static>>,
}

impl Clone for Certificate {
    fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
            rustls_certificate: self.rustls_certificate.clone(),
            // For private key, we need to recreate it from the raw bytes
            rustls_private_key: self.rustls_private_key.as_ref().map(|key| {
                rustls::pki_types::PrivateKeyDer::try_from(key.secret_der().to_vec()).unwrap()
            }),
        }
    }
}

/// In-memory certificate store
#[derive(Debug)]
pub struct CertificateStore {
    certificates: Arc<DashMap<String, Certificate>>,
}

impl CertificateInfo {
    /// Check if the certificate is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the certificate needs renewal (within threshold days)
    pub fn needs_renewal(&self, threshold_days: u32) -> bool {
        let threshold = chrono::Duration::days(threshold_days as i64);
        Utc::now() + threshold > self.expires_at
    }

    /// Get the remaining days before expiration
    pub fn days_until_expiry(&self) -> i64 {
        let duration = self.expires_at - Utc::now();
        duration.num_days()
    }
}

impl Certificate {
    /// Create a new certificate from PEM data
    pub fn from_pem(
        domain: String,
        cert_pem: &str,
        key_pem: &str,
        chain_pem: Option<&str>,
    ) -> Result<Self> {
        let cert_der = pem::parse(cert_pem).map_err(|e| {
            SslError::CertificateError(format!("Failed to parse certificate PEM: {e}"))
        })?;

        let key_der = pem::parse(key_pem).map_err(|e| {
            SslError::CertificateError(format!("Failed to parse private key PEM: {e}"))
        })?;

        // Parse certificate to get metadata
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der.contents())
            .map_err(|e| {
                SslError::CertificateError(format!("Failed to parse X.509 certificate: {e}"))
            })?;

        let issued_at = {
            let offset_dt = cert.validity.not_before.to_datetime();
            chrono::DateTime::from_timestamp(offset_dt.unix_timestamp(), 0)
                .unwrap_or_else(chrono::Utc::now)
        };
        let expires_at = {
            let offset_dt = cert.validity.not_after.to_datetime();
            chrono::DateTime::from_timestamp(offset_dt.unix_timestamp(), 0)
                .unwrap_or_else(chrono::Utc::now)
        };
        let issuer = cert.issuer().to_string();
        let serial_number = cert.serial.to_str_radix(16);

        // Generate fingerprint (SHA-256)
        let fingerprint = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(cert_der.contents());
            format!("{:x}", hasher.finalize())
        };

        let chain_der = if let Some(chain) = chain_pem {
            Some(
                pem::parse(chain)
                    .map_err(|e| {
                        SslError::CertificateError(format!(
                            "Failed to parse certificate chain PEM: {e}"
                        ))
                    })?
                    .contents()
                    .to_vec(),
            )
        } else {
            None
        };

        let info = CertificateInfo {
            domain,
            certificate: cert_der.contents().to_vec(),
            private_key: key_der.contents().to_vec(),
            certificate_chain: chain_der,
            issued_at,
            expires_at,
            issuer,
            serial_number,
            fingerprint,
        };

        // Create Rustls objects
        let rustls_certificate = Some(rustls::pki_types::CertificateDer::from(
            cert_der.contents().to_vec(),
        ));
        let rustls_private_key = Some(
            rustls::pki_types::PrivateKeyDer::try_from(key_der.contents().to_vec()).map_err(
                |e| {
                    SslError::CertificateError(format!(
                        "Failed to create Rustls private key: {e:?}"
                    ))
                },
            )?,
        );

        Ok(Certificate {
            info,
            rustls_certificate,
            rustls_private_key,
        })
    }

    /// Convert to rustls CertifiedKey for TLS usage
    pub fn to_rustls_certified_key(&self) -> Result<rustls::sign::CertifiedKey> {
        let cert_chain = if let Some(ref rustls_cert) = self.rustls_certificate {
            vec![rustls_cert.clone()]
        } else {
            return Err(SslError::TlsError(
                "No rustls certificate available".to_string(),
            ));
        };

        let private_key = if let Some(ref rustls_key) = self.rustls_private_key {
            rustls_key
        } else {
            return Err(SslError::TlsError(
                "No rustls private key available".to_string(),
            ));
        };

        let signing_key = rustls::crypto::ring::sign::any_supported_type(private_key)
            .map_err(|e| SslError::TlsError(format!("Failed to create signing key: {e}")))?;

        Ok(rustls::sign::CertifiedKey::new(cert_chain, signing_key))
    }

    /// Convert certificate to PEM format
    pub fn to_pem(&self) -> Result<(String, String, Option<String>)> {
        let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", self.info.certificate.clone()));

        let key_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", self.info.private_key.clone()));

        let chain_pem = self
            .info
            .certificate_chain
            .as_ref()
            .map(|chain| pem::encode(&pem::Pem::new("CERTIFICATE", chain.clone())));

        Ok((cert_pem, key_pem, chain_pem))
    }
}

impl CertificateStore {
    /// Create a new certificate store
    pub fn new() -> Self {
        Self {
            certificates: Arc::new(DashMap::new()),
        }
    }

    /// Add a certificate to the store
    pub fn insert(&self, domain: &str, certificate: Certificate) {
        info!("Adding certificate for domain: {}", domain);
        self.certificates.insert(domain.to_string(), certificate);
    }

    /// Get a certificate by domain
    pub fn get(&self, domain: &str) -> Option<Certificate> {
        self.certificates
            .get(domain)
            .map(|entry| entry.value().clone())
    }

    /// Remove a certificate from the store
    pub fn remove(&self, domain: &str) -> Option<Certificate> {
        debug!("Removing certificate for domain: {}", domain);
        self.certificates.remove(domain).map(|(_, cert)| cert)
    }

    /// List all domains in the store
    pub fn domains(&self) -> Vec<String> {
        self.certificates
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get certificates that need renewal
    pub fn certificates_needing_renewal(&self, threshold_days: u32) -> Vec<String> {
        self.certificates
            .iter()
            .filter(|entry| entry.value().info.needs_renewal(threshold_days))
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get expired certificates
    pub fn expired_certificates(&self) -> Vec<String> {
        self.certificates
            .iter()
            .filter(|entry| entry.value().info.is_expired())
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Update a certificate in the store
    pub fn update(&self, domain: &str, certificate: Certificate) {
        if self.certificates.contains_key(domain) {
            info!("Updating certificate for domain: {}", domain);
            self.certificates.insert(domain.to_string(), certificate);
        } else {
            warn!(
                "Attempted to update non-existent certificate for domain: {}",
                domain
            );
        }
    }

    /// Clear all certificates
    pub fn clear(&self) {
        debug!("Clearing all certificates from store");
        self.certificates.clear();
    }

    /// Get certificate count
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Check if store is empty
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }
}

impl Default for CertificateStore {
    fn default() -> Self {
        Self::new()
    }
}
