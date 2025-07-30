use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;
use std::env;

use super::provider::{DnsError, DnsProvider, DnsRecord};

/// Azure DNS provider for ACME DNS-01 challenges
pub struct AzureDnsProvider {
    client: Client,
    subscription_id: String,
    resource_group: String,
    zone_name: String,
    client_id: String,
    client_secret: String,
    tenant_id: String,
    access_token: Option<String>,
}

impl AzureDnsProvider {
    /// Create a new Azure DNS provider
    pub fn new(
        subscription_id: String,
        resource_group: String,
        zone_name: String,
        client_id: String,
        client_secret: String,
        tenant_id: String,
    ) -> Self {
        Self {
            client: Client::new(),
            subscription_id,
            resource_group,
            zone_name,
            client_id,
            client_secret,
            tenant_id,
            access_token: None,
        }
    }

    /// Create Azure DNS provider from environment variables
    pub async fn from_env() -> Result<Self, DnsError> {
        let subscription_id = env::var("AZURE_SUBSCRIPTION_ID").map_err(|_| {
            DnsError::ConfigurationError(
                "AZURE_SUBSCRIPTION_ID environment variable not set".to_string(),
            )
        })?;

        let resource_group = env::var("AZURE_RESOURCE_GROUP").map_err(|_| {
            DnsError::ConfigurationError(
                "AZURE_RESOURCE_GROUP environment variable not set".to_string(),
            )
        })?;

        let zone_name = env::var("AZURE_DNS_ZONE_NAME").map_err(|_| {
            DnsError::ConfigurationError(
                "AZURE_DNS_ZONE_NAME environment variable not set".to_string(),
            )
        })?;

        let client_id = env::var("AZURE_CLIENT_ID").map_err(|_| {
            DnsError::ConfigurationError("AZURE_CLIENT_ID environment variable not set".to_string())
        })?;

        let client_secret = env::var("AZURE_CLIENT_SECRET").map_err(|_| {
            DnsError::ConfigurationError(
                "AZURE_CLIENT_SECRET environment variable not set".to_string(),
            )
        })?;

        let tenant_id = env::var("AZURE_TENANT_ID").map_err(|_| {
            DnsError::ConfigurationError("AZURE_TENANT_ID environment variable not set".to_string())
        })?;

        Ok(Self::new(
            subscription_id,
            resource_group,
            zone_name,
            client_id,
            client_secret,
            tenant_id,
        ))
    }

    /// Get Azure AD access token
    async fn get_access_token(&mut self) -> Result<String, DnsError> {
        if let Some(token) = &self.access_token {
            return Ok(token.clone());
        }

        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        );

        let form_data = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("scope", "https://management.azure.com/.default"),
            ("grant_type", "client_credentials"),
        ];

        let response = self
            .client
            .post(&token_url)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(DnsError::AuthenticationError(format!(
                "Failed to get Azure access token: {error_text}"
            )));
        }

        let token_data: serde_json::Value = response
            .json()
            .await
            .map_err(|e| DnsError::AuthenticationError(e.to_string()))?;

        let access_token = token_data["access_token"].as_str().ok_or_else(|| {
            DnsError::AuthenticationError("No access token in response".to_string())
        })?;

        self.access_token = Some(access_token.to_string());
        Ok(access_token.to_string())
    }
}

#[async_trait]
impl DnsProvider for AzureDnsProvider {
    fn name(&self) -> &str {
        "Azure DNS"
    }

    async fn is_available(&self) -> bool {
        // Test by trying to get an access token
        let mut provider = Self::new(
            self.subscription_id.clone(),
            self.resource_group.clone(),
            self.zone_name.clone(),
            self.client_id.clone(),
            self.client_secret.clone(),
            self.tenant_id.clone(),
        );

        provider.get_access_token().await.is_ok()
    }

    async fn create_txt_record(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let mut provider = self.clone();
        let access_token = provider.get_access_token().await?;

        // Extract record name relative to zone (remove zone suffix)
        let record_name = if record.name.ends_with(&format!(".{}", self.zone_name)) {
            record
                .name
                .strip_suffix(&format!(".{}", self.zone_name))
                .unwrap_or(&record.name)
        } else {
            &record.name
        };

        let url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/TXT/{}?api-version=2018-05-01",
            self.subscription_id,
            self.resource_group,
            self.zone_name,
            record_name
        );

        let record_data = json!({
            "properties": {
                "TTL": record.ttl,
                "TXTRecords": [
                    {
                        "value": [record.content]
                    }
                ]
            }
        });

        let response = self
            .client
            .put(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/json")
            .json(&record_data)
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(DnsError::ApiError(format!(
                "Azure DNS API error: {error_text}"
            )))
        }
    }

    async fn delete_txt_record(&self, name: &str) -> Result<(), DnsError> {
        let mut provider = self.clone();
        let access_token = provider.get_access_token().await?;

        // Extract record name relative to zone
        let record_name = if name.ends_with(&format!(".{}", self.zone_name)) {
            name.strip_suffix(&format!(".{}", self.zone_name))
                .unwrap_or(name)
        } else {
            name
        };

        let url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/TXT/{}?api-version=2018-05-01",
            self.subscription_id,
            self.resource_group,
            self.zone_name,
            record_name
        );

        let response = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(DnsError::ApiError(format!(
                "Failed to delete Azure DNS record: {error_text}"
            )))
        }
    }

    fn propagation_delay(&self) -> u64 {
        120 // Azure DNS typically takes 2 minutes for propagation
    }
}

// Need to implement Clone for the provider since we need mutable access for token management
impl Clone for AzureDnsProvider {
    fn clone(&self) -> Self {
        Self {
            client: Client::new(),
            subscription_id: self.subscription_id.clone(),
            resource_group: self.resource_group.clone(),
            zone_name: self.zone_name.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            tenant_id: self.tenant_id.clone(),
            access_token: self.access_token.clone(),
        }
    }
}
