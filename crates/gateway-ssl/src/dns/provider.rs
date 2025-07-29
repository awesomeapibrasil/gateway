use async_trait::async_trait;
use std::error::Error;
use std::fmt;

/// DNS record structure
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub content: String,
    pub ttl: u32,
}

/// DNS provider error
#[derive(Debug)]
pub enum DnsError {
    ApiError(String),
    AuthenticationError(String),
    RecordNotFound(String),
    NetworkError(String),
    ConfigurationError(String),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::ApiError(msg) => write!(f, "DNS API error: {msg}"),
            DnsError::AuthenticationError(msg) => write!(f, "DNS authentication error: {msg}"),
            DnsError::RecordNotFound(msg) => write!(f, "DNS record not found: {msg}"),
            DnsError::NetworkError(msg) => write!(f, "DNS network error: {msg}"),
            DnsError::ConfigurationError(msg) => write!(f, "DNS configuration error: {msg}"),
        }
    }
}

impl Error for DnsError {}

/// Trait for DNS providers to implement ACME DNS-01 challenges
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Provider name for identification
    fn name(&self) -> &str;

    /// Check if the provider is properly configured and available
    async fn is_available(&self) -> bool;

    /// Create or update a TXT record for ACME challenge
    async fn create_txt_record(&self, record: &DnsRecord) -> Result<(), DnsError>;

    /// Delete a TXT record after ACME challenge completion
    async fn delete_txt_record(&self, name: &str) -> Result<(), DnsError>;

    /// Get the propagation delay in seconds for this provider
    fn propagation_delay(&self) -> u64 {
        120 // Default 2 minutes
    }
}

/// DNS provider factory for creating provider instances
pub struct DnsProviderFactory;

impl DnsProviderFactory {
    /// Auto-detect and create available DNS providers based on environment variables
    pub async fn create_available_providers() -> Vec<Box<dyn DnsProvider>> {
        let mut providers: Vec<Box<dyn DnsProvider>> = Vec::new();

        // Check CloudFlare
        if let Ok(provider) = crate::dns::cloudflare::CloudFlareProvider::from_env().await {
            if provider.is_available().await {
                providers.push(Box::new(provider));
            }
        }

        // Check Route53
        if let Ok(provider) = crate::dns::route53::Route53Provider::from_env().await {
            if provider.is_available().await {
                providers.push(Box::new(provider));
            }
        }

        // Check Azure DNS
        if let Ok(provider) = crate::dns::azure::AzureDnsProvider::from_env().await {
            if provider.is_available().await {
                providers.push(Box::new(provider));
            }
        }

        // Check Oracle Cloud DNS
        if let Ok(provider) = crate::dns::oracle::OracleDnsProvider::from_env().await {
            if provider.is_available().await {
                providers.push(Box::new(provider));
            }
        }

        providers
    }

    /// Create a specific provider by name
    pub async fn create_provider(provider_name: &str) -> Result<Box<dyn DnsProvider>, DnsError> {
        match provider_name.to_lowercase().as_str() {
            "cloudflare" => {
                let provider = crate::dns::cloudflare::CloudFlareProvider::from_env()
                    .await
                    .map_err(|e| DnsError::ConfigurationError(e.to_string()))?;
                Ok(Box::new(provider))
            }
            "route53" => {
                let provider = crate::dns::route53::Route53Provider::from_env()
                    .await
                    .map_err(|e| DnsError::ConfigurationError(e.to_string()))?;
                Ok(Box::new(provider))
            }
            "azure" => {
                let provider = crate::dns::azure::AzureDnsProvider::from_env()
                    .await
                    .map_err(|e| DnsError::ConfigurationError(e.to_string()))?;
                Ok(Box::new(provider))
            }
            "oracle" => {
                let provider = crate::dns::oracle::OracleDnsProvider::from_env()
                    .await
                    .map_err(|e| DnsError::ConfigurationError(e.to_string()))?;
                Ok(Box::new(provider))
            }
            _ => Err(DnsError::ConfigurationError(format!(
                "Unknown DNS provider: {provider_name}"
            ))),
        }
    }
}
