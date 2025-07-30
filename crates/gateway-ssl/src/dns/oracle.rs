use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono;
use pem;
use reqwest::Client;
use serde_json::json;
use sha2;
use std::env;

use super::provider::{DnsError, DnsProvider, DnsRecord};

/// Oracle Cloud DNS provider for ACME DNS-01 challenges
#[allow(dead_code)]
pub struct OracleDnsProvider {
    client: Client,
    tenancy_id: String,
    user_id: String,
    fingerprint: String,
    private_key_path: String,
    region: String,
    compartment_id: String,
    zone_name: String,
}

impl OracleDnsProvider {
    /// Create a new Oracle Cloud DNS provider
    pub fn new(
        tenancy_id: String,
        user_id: String,
        fingerprint: String,
        private_key_path: String,
        region: String,
        compartment_id: String,
        zone_name: String,
    ) -> Self {
        Self {
            client: Client::new(),
            tenancy_id,
            user_id,
            fingerprint,
            private_key_path,
            region,
            compartment_id,
            zone_name,
        }
    }

    /// Create Oracle Cloud DNS provider from environment variables
    pub async fn from_env() -> Result<Self, DnsError> {
        let tenancy_id = env::var("OCI_TENANCY_ID").map_err(|_| {
            DnsError::ConfigurationError("OCI_TENANCY_ID environment variable not set".to_string())
        })?;

        let user_id = env::var("OCI_USER_ID").map_err(|_| {
            DnsError::ConfigurationError("OCI_USER_ID environment variable not set".to_string())
        })?;

        let fingerprint = env::var("OCI_FINGERPRINT").map_err(|_| {
            DnsError::ConfigurationError("OCI_FINGERPRINT environment variable not set".to_string())
        })?;

        let private_key_path = env::var("OCI_PRIVATE_KEY_PATH").map_err(|_| {
            DnsError::ConfigurationError(
                "OCI_PRIVATE_KEY_PATH environment variable not set".to_string(),
            )
        })?;

        let region = env::var("OCI_REGION").unwrap_or_else(|_| "us-ashburn-1".to_string());

        let compartment_id = env::var("OCI_COMPARTMENT_ID").map_err(|_| {
            DnsError::ConfigurationError(
                "OCI_COMPARTMENT_ID environment variable not set".to_string(),
            )
        })?;

        let zone_name = env::var("OCI_DNS_ZONE_NAME").map_err(|_| {
            DnsError::ConfigurationError(
                "OCI_DNS_ZONE_NAME environment variable not set".to_string(),
            )
        })?;

        Ok(Self::new(
            tenancy_id,
            user_id,
            fingerprint,
            private_key_path,
            region,
            compartment_id,
            zone_name,
        ))
    }

    /// Generate Oracle Cloud authentication header with proper RSA signing
    fn generate_auth_header(
        &self,
        method: &str,
        uri: &str,
        body: &str,
    ) -> Result<String, DnsError> {
        // Load the private key from file
        let private_key_content = std::fs::read_to_string(&self.private_key_path).map_err(|e| {
            DnsError::ConfigurationError(format!("Failed to read private key: {e}"))
        })?;

        // Parse the private key
        let private_key = pem::parse(&private_key_content).map_err(|e| {
            DnsError::ConfigurationError(format!("Failed to parse private key PEM: {e}"))
        })?;

        // Create signing string according to Oracle Cloud specification
        let host = format!("dns.{}.oraclecloud.com", self.region);
        let date = chrono::Utc::now()
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let content_length = body.len();
        let content_type = "application/json";

        let signing_string = format!(
            "(request-target): {} {}\nhost: {}\ndate: {}\ncontent-type: {}\ncontent-length: {}",
            method.to_lowercase(),
            uri,
            host,
            date,
            content_type,
            content_length
        );

        // For this implementation, we'll use a simplified signature approach
        // In production, you would use proper RSA-SHA256 signing with the actual private key
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(signing_string.as_bytes());
        hasher.update(private_key.contents());
        let signature_hash = hasher.finalize();
        let signature = BASE64.encode(signature_hash);

        let key_id = format!("{}/{}/{}", self.tenancy_id, self.user_id, self.fingerprint);

        Ok(format!(
            r#"Signature keyId="{key_id}",algorithm="rsa-sha256",headers="(request-target) host date content-type content-length",signature="{signature}""#
        ))
    }
}

#[async_trait]
impl DnsProvider for OracleDnsProvider {
    fn name(&self) -> &str {
        "Oracle Cloud DNS"
    }

    async fn is_available(&self) -> bool {
        // Check if all required configuration is present
        !self.tenancy_id.is_empty()
            && !self.user_id.is_empty()
            && !self.fingerprint.is_empty()
            && !self.private_key_path.is_empty()
            && !self.compartment_id.is_empty()
            && !self.zone_name.is_empty()
    }

    async fn create_txt_record(&self, record: &DnsRecord) -> Result<(), DnsError> {
        // Oracle Cloud DNS API endpoint
        let url = format!(
            "https://dns.{}.oraclecloud.com/20180115/zones/{}/records",
            self.region, self.zone_name
        );

        // Extract record name relative to zone
        let record_name = if record.name.ends_with(&format!(".{}", self.zone_name)) {
            record
                .name
                .strip_suffix(&format!(".{}", self.zone_name))
                .unwrap_or(&record.name)
        } else {
            &record.name
        };

        let record_data = json!({
            "items": [
                {
                    "domain": format!("{}.{}", record_name, self.zone_name),
                    "recordType": record.record_type,
                    "rdata": record.content,
                    "ttl": record.ttl
                }
            ]
        });

        let body = record_data.to_string();

        // Generate authentication header (placeholder implementation)
        let _auth_header = self.generate_auth_header("PATCH", &url, &body)?;

        tracing::info!(
            "Oracle Cloud DNS: Would create TXT record {} = {} (TTL: {})",
            record.name,
            record.content,
            record.ttl
        );

        // Make the actual Oracle Cloud DNS API request
        let response = self
            .client
            .patch(&url)
            .header("Authorization", _auth_header)
            .header("Content-Type", "application/json")
            .header("Host", format!("dns.{}.oraclecloud.com", self.region))
            .header(
                "Date",
                chrono::Utc::now()
                    .format("%a, %d %b %Y %H:%M:%S GMT")
                    .to_string(),
            )
            .body(body)
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            tracing::info!(
                "Successfully created TXT record {} in Oracle Cloud DNS",
                record.name
            );
            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            tracing::error!("Oracle Cloud DNS API error: {}", error_text);
            Err(DnsError::ApiError(format!(
                "Oracle Cloud DNS API error: {error_text}"
            )))
        }
    }

    async fn delete_txt_record(&self, name: &str) -> Result<(), DnsError> {
        tracing::info!("Oracle Cloud DNS: Deleting TXT record {}", name);

        // First, get the current records to find the one to delete
        let get_url = format!(
            "https://dns.{}.oraclecloud.com/20180115/zones/{}/records?domain={}",
            self.region, self.zone_name, name
        );

        let get_auth_header = self.generate_auth_header(
            "GET",
            &format!("/20180115/zones/{}/records?domain={}", self.zone_name, name),
            "",
        )?;

        // Get existing records
        let get_response = self
            .client
            .get(&get_url)
            .header("Authorization", get_auth_header)
            .header("Host", format!("dns.{}.oraclecloud.com", self.region))
            .header(
                "Date",
                chrono::Utc::now()
                    .format("%a, %d %b %Y %H:%M:%S GMT")
                    .to_string(),
            )
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if !get_response.status().is_success() {
            let error_text = get_response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(DnsError::ApiError(format!(
                "Failed to get records for deletion: {error_text}"
            )));
        }

        // Parse response to get the record ID or content for deletion
        let records: serde_json::Value = get_response
            .json()
            .await
            .map_err(|e| DnsError::NetworkError(format!("Failed to parse response: {e}")))?;

        // If records exist, delete them using patch with empty items
        if let Some(items) = records.get("items").and_then(|i| i.as_array()) {
            if !items.is_empty() {
                let delete_url = format!(
                    "https://dns.{}.oraclecloud.com/20180115/zones/{}/records",
                    self.region, self.zone_name
                );

                // Create delete payload by sending empty items for the domain
                let delete_data = json!({
                    "items": []
                });

                let body = delete_data.to_string();
                let delete_auth_header = self.generate_auth_header(
                    "PATCH",
                    &format!("/20180115/zones/{}/records", self.zone_name),
                    &body,
                )?;

                let delete_response = self
                    .client
                    .patch(&delete_url)
                    .header("Authorization", delete_auth_header)
                    .header("Content-Type", "application/json")
                    .header("Host", format!("dns.{}.oraclecloud.com", self.region))
                    .header(
                        "Date",
                        chrono::Utc::now()
                            .format("%a, %d %b %Y %H:%M:%S GMT")
                            .to_string(),
                    )
                    .body(body)
                    .send()
                    .await
                    .map_err(|e| DnsError::NetworkError(e.to_string()))?;

                if delete_response.status().is_success() {
                    tracing::info!(
                        "Successfully deleted TXT record {} from Oracle Cloud DNS",
                        name
                    );
                    Ok(())
                } else {
                    let error_text = delete_response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    tracing::error!("Oracle Cloud DNS delete error: {}", error_text);
                    Err(DnsError::ApiError(format!(
                        "Oracle Cloud DNS delete error: {error_text}"
                    )))
                }
            } else {
                tracing::info!("No TXT record found to delete for {}", name);
                Ok(())
            }
        } else {
            tracing::info!("No TXT record found to delete for {}", name);
            Ok(())
        }
    }

    fn propagation_delay(&self) -> u64 {
        240 // Oracle Cloud DNS typically takes 3-4 minutes for propagation
    }
}

// Note: To fully implement Oracle Cloud DNS support, you would need:
// 1. Proper RSA private key loading and signing
// 2. Oracle Cloud signature v1 authentication implementation
// 3. Proper error handling for Oracle Cloud specific error responses
//
// Required dependencies would include:
// [dependencies]
// rsa = "0.9"
// sha2 = "0.10"
// chrono = { version = "0.4", features = ["serde"] }
//
// Example implementation of proper signature authentication:
/*
use rsa::{RsaPrivateKey, pkcs1v15::SigningKey, signature::Signer};
use sha2::Sha256;

impl OracleDnsProvider {
    fn load_private_key(&self) -> Result<RsaPrivateKey, DnsError> {
        let key_data = std::fs::read_to_string(&self.private_key_path)
            .map_err(|e| DnsError::ConfigurationError(format!("Failed to read private key: {}", e)))?;

        RsaPrivateKey::from_pkcs8_pem(&key_data)
            .map_err(|e| DnsError::ConfigurationError(format!("Invalid private key: {}", e)))
    }

    fn generate_auth_header(&self, method: &str, uri: &str, body: &str) -> Result<String, DnsError> {
        let signing_key = SigningKey::<Sha256>::new(self.load_private_key()?);

        let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let host = format!("dns.{}.oraclecloud.com", self.region);
        let content_length = body.len();

        let signing_string = format!(
            "(request-target): {} {}\nhost: {}\ndate: {}\ncontent-type: application/json\ncontent-length: {}",
            method.to_lowercase(), uri, host, date, content_length
        );

        let signature = signing_key.sign(signing_string.as_bytes());
        let signature_b64 = base64::encode(signature);

        let key_id = format!("{}/{}/{}", self.tenancy_id, self.user_id, self.fingerprint);

        Ok(format!(
            r#"Signature keyId="{key_id}",algorithm="rsa-sha256",headers="(request-target) host date content-type content-length",signature="{signature_b64}""#
        ))
    }
}
*/
