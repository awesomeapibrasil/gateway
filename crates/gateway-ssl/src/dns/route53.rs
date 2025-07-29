use async_trait::async_trait;
use aws_sdk_route53::Client;
use std::env;

use super::provider::{DnsError, DnsProvider, DnsRecord};

/// AWS Route53 DNS provider for ACME DNS-01 challenges
pub struct Route53Provider {
    client: Client,
    hosted_zone_id: Option<String>,
}

impl Route53Provider {
    /// Create a new Route53 provider with AWS client
    pub async fn new(hosted_zone_id: Option<String>) -> Result<Self, DnsError> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = Client::new(&config);

        Ok(Self {
            client,
            hosted_zone_id,
        })
    }

    /// Create Route53 provider from environment variables
    pub async fn from_env() -> Result<Self, DnsError> {
        // Validate required AWS credentials are set
        env::var("AWS_ACCESS_KEY_ID").map_err(|_| {
            DnsError::ConfigurationError(
                "AWS_ACCESS_KEY_ID environment variable not set".to_string(),
            )
        })?;

        env::var("AWS_SECRET_ACCESS_KEY").map_err(|_| {
            DnsError::ConfigurationError(
                "AWS_SECRET_ACCESS_KEY environment variable not set".to_string(),
            )
        })?;

        let hosted_zone_id = env::var("AWS_HOSTED_ZONE_ID").ok();

        Self::new(hosted_zone_id).await
    }

    /// Find hosted zone for domain
    async fn find_hosted_zone_for_domain(&self, domain: &str) -> Result<String, DnsError> {
        if let Some(zone_id) = &self.hosted_zone_id {
            return Ok(zone_id.clone());
        }

        // Auto-discover hosted zone
        let mut list_req = self.client.list_hosted_zones();
        let mut best_match = None;
        let mut best_match_length = 0;

        loop {
            let response = list_req
                .send()
                .await
                .map_err(|e| DnsError::ProviderError(format!("Route53 API error: {e}")))?;

            for zone in response.hosted_zones() {
                let zone_name = zone.name();
                let zone_name = zone_name.trim_end_matches('.');
                if domain.ends_with(zone_name) && zone_name.len() > best_match_length {
                    let zone_id = zone.id();
                    best_match = Some(zone_id.trim_start_matches("/hostedzone/").to_string());
                    best_match_length = zone_name.len();
                }
            }

            if response.is_truncated() && response.next_marker().is_some() {
                list_req = self
                    .client
                    .list_hosted_zones()
                    .marker(response.next_marker().unwrap());
            } else {
                break;
            }
        }

        best_match.ok_or_else(|| {
            DnsError::ConfigurationError(format!("No hosted zone found for domain: {domain}"))
        })
    }
}

#[async_trait]
impl DnsProvider for Route53Provider {
    fn name(&self) -> &str {
        "Route53"
    }

    async fn is_available(&self) -> bool {
        // Test AWS connectivity by listing hosted zones
        self.client.list_hosted_zones().send().await.is_ok()
    }

    async fn create_txt_record(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let hosted_zone_id = self.find_hosted_zone_for_domain(&record.name).await?;

        use aws_sdk_route53::types::{
            Change, ChangeAction, ResourceRecord, ResourceRecordSet, RrType,
        };

        let resource_record = ResourceRecord::builder()
            .value(format!("\"{}\"", record.content))
            .build()
            .map_err(|e| {
                DnsError::ProviderError(format!("Failed to build resource record: {e}"))
            })?;

        let record_set = ResourceRecordSet::builder()
            .name(&record.name)
            .r#type(RrType::Txt)
            .ttl(record.ttl as i64)
            .resource_records(resource_record)
            .build()
            .map_err(|e| DnsError::ProviderError(format!("Failed to build record set: {e}")))?;

        let change = Change::builder()
            .action(ChangeAction::Create)
            .resource_record_set(record_set)
            .build()
            .map_err(|e| DnsError::ProviderError(format!("Failed to build change: {e}")))?;

        let response = self
            .client
            .change_resource_record_sets()
            .hosted_zone_id(&hosted_zone_id)
            .change_batch(
                aws_sdk_route53::types::ChangeBatch::builder()
                    .changes(change)
                    .build()
                    .map_err(|e| {
                        DnsError::ProviderError(format!("Failed to build change batch: {e}"))
                    })?,
            )
            .send()
            .await
            .map_err(|e| DnsError::ProviderError(format!("Route53 API error: {e}")))?;

        tracing::info!(
            "Route53: Created TXT record {} = {} (TTL: {}) - Change ID: {}",
            record.name,
            record.content,
            record.ttl,
            response
                .change_info()
                .map(|ci| ci.id())
                .unwrap_or("unknown")
        );

        Ok(())
    }

    async fn delete_txt_record(&self, name: &str) -> Result<(), DnsError> {
        let hosted_zone_id = self.find_hosted_zone_for_domain(name).await?;

        use aws_sdk_route53::types::{Change, ChangeAction, RrType};

        // First, find the existing TXT record
        let list_response = self
            .client
            .list_resource_record_sets()
            .hosted_zone_id(&hosted_zone_id)
            .start_record_name(name)
            .start_record_type(RrType::Txt)
            .send()
            .await
            .map_err(|e| DnsError::ProviderError(format!("Route53 API error: {e}")))?;

        for record_set in list_response.resource_record_sets() {
            if record_set.name() == name && record_set.r#type() == &RrType::Txt {
                let change = Change::builder()
                    .action(ChangeAction::Delete)
                    .resource_record_set(record_set.clone())
                    .build()
                    .map_err(|e| {
                        DnsError::ProviderError(format!("Failed to build delete change: {e}"))
                    })?;

                let response = self
                    .client
                    .change_resource_record_sets()
                    .hosted_zone_id(&hosted_zone_id)
                    .change_batch(
                        aws_sdk_route53::types::ChangeBatch::builder()
                            .changes(change)
                            .build()
                            .map_err(|e| {
                                DnsError::ProviderError(format!(
                                    "Failed to build change batch: {e}"
                                ))
                            })?,
                    )
                    .send()
                    .await
                    .map_err(|e| DnsError::ProviderError(format!("Route53 API error: {e}")))?;

                tracing::info!(
                    "Route53: Deleted TXT record {} - Change ID: {}",
                    name,
                    response
                        .change_info()
                        .map(|ci| ci.id())
                        .unwrap_or("unknown")
                );

                return Ok(());
            }
        }

        tracing::warn!("Route53: TXT record {} not found for deletion", name);
        Ok(())
    }

    fn propagation_delay(&self) -> u64 {
        180 // Route53 typically takes 2-3 minutes for propagation
    }
}
