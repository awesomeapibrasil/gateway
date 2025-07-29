use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// SSL configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SslConfig {
    pub enabled: bool,
    pub auto_ssl: AutoSslConfig,
    pub certificate: CertificateConfig,
    pub vault: Option<VaultConfig>,
    pub acme: AcmeConfig,
}

/// Auto-SSL configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoSslConfig {
    pub enabled: bool,
    pub domains: Vec<String>,
    pub email: String,
    pub staging: bool,
    pub renewal_threshold_days: u32,
    pub challenge_type: String, // "http-01", "dns-01", "tls-alpn-01"
    pub challenge_port: u16,
}

/// Certificate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateConfig {
    pub storage_backend: String, // "database", "vault", "filesystem"
    pub cache_directory: String,
    pub watch_external_updates: bool,
    pub auto_reload: bool,
    pub reload_interval: Duration,
}

/// Vault configuration for certificate storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    pub address: String,
    pub token: Option<String>,
    pub mount_path: String,
    pub certificate_path: String,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub ca_cert_path: Option<String>,
    pub skip_verify: bool,
    pub timeout: Duration,
    pub auth_method: VaultAuthMethod,
}

/// Vault authentication method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultAuthMethod {
    pub method_type: String, // "token", "kubernetes", "ldap", "userpass"
    pub config: HashMap<String, String>,
}

/// ACME configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    pub directory_url: String,
    pub contact_email: String,
    pub terms_of_service_agreed: bool,
    pub key_type: String, // "rsa2048", "rsa4096", "ecdsa256", "ecdsa384"
    pub challenge_timeout: Duration,
    pub propagation_timeout: Duration,
    pub dns_providers: HashMap<String, DnsProviderConfig>,
}

/// DNS provider configuration for DNS-01 challenges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProviderConfig {
    pub provider: String, // "cloudflare", "route53", "godaddy", etc.
    pub config: HashMap<String, String>,
}


impl Default for AutoSslConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domains: Vec::new(),
            email: String::new(),
            staging: true,
            renewal_threshold_days: 30,
            challenge_type: "http-01".to_string(),
            challenge_port: 80,
        }
    }
}

impl Default for CertificateConfig {
    fn default() -> Self {
        Self {
            storage_backend: "database".to_string(),
            cache_directory: "/tmp/gateway-certificates".to_string(),
            watch_external_updates: true,
            auto_reload: true,
            reload_interval: Duration::from_secs(300), // 5 minutes
        }
    }
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
            contact_email: String::new(),
            terms_of_service_agreed: false,
            key_type: "ecdsa256".to_string(),
            challenge_timeout: Duration::from_secs(300),
            propagation_timeout: Duration::from_secs(120),
            dns_providers: HashMap::new(),
        }
    }
}
