use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;
use std::env;

use super::provider::{DnsError, DnsProvider, DnsRecord};

/// CloudFlare DNS provider for ACME DNS-01 challenges
pub struct CloudFlareProvider {
    client: Client,
    api_token: String,
    zone_id: String,
}

impl CloudFlareProvider {
    /// Create a new CloudFlare provider
    pub fn new(api_token: String, zone_id: String) -> Self {
        Self {
            client: Client::new(),
            api_token,
            zone_id,
        }
    }

    /// Create CloudFlare provider from environment variables
    pub async fn from_env() -> Result<Self, DnsError> {
        let api_token = env::var("CF_API_TOKEN").map_err(|_| {
            DnsError::ConfigurationError("CF_API_TOKEN environment variable not set".to_string())
        })?;

        let zone_id = env::var("CF_ZONE_ID").map_err(|_| {
            DnsError::ConfigurationError("CF_ZONE_ID environment variable not set".to_string())
        })?;

        Ok(Self::new(api_token, zone_id))
    }
}

#[async_trait]
impl DnsProvider for CloudFlareProvider {
    fn name(&self) -> &str {
        "CloudFlare"
    }

    async fn is_available(&self) -> bool {
        // Test API connectivity by trying to get zone info
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}",
            self.zone_id
        );

        match self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
        {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    }

    async fn create_txt_record(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        );

        let record_data = json!({
            "type": record.record_type,
            "name": record.name,
            "content": record.content,
            "ttl": record.ttl
        });

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
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
                "CloudFlare API error: {}",
                error_text
            )))
        }
    }

    async fn delete_txt_record(&self, name: &str) -> Result<(), DnsError> {
        // First, find the record ID by listing records with the name
        let list_url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type=TXT&name={}",
            self.zone_id, name
        );

        let list_response = self
            .client
            .get(&list_url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if !list_response.status().is_success() {
            return Err(DnsError::ApiError("Failed to list DNS records".to_string()));
        }

        let list_data: serde_json::Value = list_response
            .json()
            .await
            .map_err(|e| DnsError::ApiError(format!("Failed to parse response: {}", e)))?;

        let records = list_data["result"]
            .as_array()
            .ok_or_else(|| DnsError::ApiError("Invalid response format".to_string()))?;

        for record in records {
            if let Some(record_id) = record["id"].as_str() {
                let delete_url = format!(
                    "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                    self.zone_id, record_id
                );

                let delete_response = self
                    .client
                    .delete(&delete_url)
                    .header("Authorization", format!("Bearer {}", self.api_token))
                    .send()
                    .await
                    .map_err(|e| DnsError::NetworkError(e.to_string()))?;

                if !delete_response.status().is_success() {
                    let error_text = delete_response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    return Err(DnsError::ApiError(format!(
                        "Failed to delete record: {}",
                        error_text
                    )));
                }
            }
        }

        Ok(())
    }

    fn propagation_delay(&self) -> u64 {
        60 // CloudFlare typically propagates quickly (1 minute)
    }
}
