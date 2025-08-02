//! Worker Client
//!
//! gRPC client for communicating with the Worker service.

use anyhow::Result;
use std::time::Duration;
use tonic::transport::Channel;
use tracing::{info, warn};

// Include generated protobuf types
pub mod proto {
    tonic::include_proto!("gateway_worker");
}

use proto::{
    gateway_worker_service_client::GatewayWorkerServiceClient,
    *,
};

/// Configuration for Worker client
#[derive(Debug, Clone)]
pub struct WorkerClientConfig {
    pub worker_address: String,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub retry_attempts: u32,
}

impl Default for WorkerClientConfig {
    fn default() -> Self {
        Self {
            worker_address: "http://localhost:50051".to_string(),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            retry_attempts: 3,
        }
    }
}

/// Worker Client for Gateway-Worker communication
pub struct WorkerClient {
    client: GatewayWorkerServiceClient<Channel>,
    config: WorkerClientConfig,
    gateway_id: String,
}

impl WorkerClient {
    /// Create a new Worker client
    pub async fn new(config: WorkerClientConfig, gateway_id: String) -> Result<Self> {
        info!("Connecting to Worker service at: {}", config.worker_address);
        
        let channel = Channel::from_shared(config.worker_address.clone())?
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .connect()
            .await?;

        let client = GatewayWorkerServiceClient::new(channel);

        info!("Successfully connected to Worker service");
        
        Ok(Self {
            client,
            config,
            gateway_id,
        })
    }

    /// Check health of Worker service
    pub async fn health_check(&mut self) -> Result<bool> {
        let request = tonic::Request::new(HealthCheckRequest {
            service: "gateway-worker".to_string(),
        });

        match self.client.health_check(request).await {
            Ok(response) => {
                let health_response = response.into_inner();
                Ok(health_response.status == health_check_response::ServingStatus::Serving as i32)
            }
            Err(e) => {
                warn!("Worker health check failed: {}", e);
                Ok(false)
            }
        }
    }

    /// Get certificate from Worker
    pub async fn get_certificate(&mut self, domain: &str, cert_type: &str) -> Result<CertificateData> {
        info!("Requesting certificate for domain: {} (type: {})", domain, cert_type);
        
        let request = tonic::Request::new(CertificateRequest {
            domain: domain.to_string(),
            certificate_type: cert_type.to_string(),
        });

        let response = self.client.get_certificate(request).await?;
        let cert_response = response.into_inner();

        Ok(CertificateData {
            domain: cert_response.domain,
            certificate_pem: cert_response.certificate_pem,
            private_key_pem: cert_response.private_key_pem,
            certificate_chain_pem: if cert_response.certificate_chain_pem.is_empty() {
                None
            } else {
                Some(cert_response.certificate_chain_pem)
            },
            expires_at: cert_response.expires_at,
            is_temporary: cert_response.is_temporary,
            certificate_id: cert_response.certificate_id,
        })
    }

    /// Watch for certificate updates from Worker
    pub async fn watch_certificate_updates(&mut self, domains: Vec<String>) -> Result<tonic::Streaming<CertificateUpdate>> {
        info!("Starting certificate watch for domains: {:?}", domains);
        
        let request = tonic::Request::new(CertificateWatchRequest {
            gateway_id: self.gateway_id.clone(),
            domains,
        });

        let response = self.client.watch_certificate_updates(request).await?;
        let stream = response.into_inner();
        
        Ok(stream)
    }

    /// Get configuration from Worker
    pub async fn get_configuration(&mut self, config_type: &str, config_version: Option<&str>) -> Result<ConfigurationData> {
        info!("Requesting configuration type: {}", config_type);
        
        let request = tonic::Request::new(ConfigurationRequest {
            gateway_id: self.gateway_id.clone(),
            config_type: config_type.to_string(),
            config_version: config_version.unwrap_or("").to_string(),
        });

        let response = self.client.get_configuration(request).await?;
        let config_response = response.into_inner();

        Ok(ConfigurationData {
            config_type: config_response.config_type,
            config_version: config_response.config_version,
            config_data: config_response.config_data,
            updated_at: config_response.updated_at,
            checksum: config_response.checksum,
        })
    }

    /// Watch for configuration updates from Worker
    pub async fn watch_configuration_updates(&mut self, config_types: Vec<String>) -> Result<tonic::Streaming<ConfigurationUpdate>> {
        info!("Starting configuration watch for types: {:?}", config_types);
        
        let request = tonic::Request::new(ConfigurationWatchRequest {
            gateway_id: self.gateway_id.clone(),
            config_types,
        });

        let response = self.client.watch_configuration_updates(request).await?;
        let stream = response.into_inner();
        
        Ok(stream)
    }

    /// Send logs to Worker
    pub async fn send_logs(&mut self, logs: Vec<LogEntry>) -> Result<LogProcessingResponse> {
        info!("Sending {} log entries to Worker", logs.len());
        
        use tokio_stream::iter;
        
        let log_stream = iter(logs);
        let request = tonic::Request::new(log_stream);

        let response = self.client.send_logs(request).await?;
        let log_response = response.into_inner();
        
        if !log_response.success {
            warn!("Log processing had errors: {}", log_response.message);
        }
        
        Ok(log_response)
    }

    /// Get metrics from Worker
    pub async fn get_metrics(&mut self, timestamp_from: i64, timestamp_to: i64) -> Result<Vec<MetricData>> {
        info!("Requesting metrics from Worker");
        
        let request = tonic::Request::new(MetricsRequest {
            gateway_id: self.gateway_id.clone(),
            timestamp_from,
            timestamp_to,
        });

        let response = self.client.get_metrics(request).await?;
        let metrics_response = response.into_inner();
        
        Ok(metrics_response.metrics)
    }
}

/// Certificate data structure for Gateway use
#[derive(Debug, Clone)]
pub struct CertificateData {
    pub domain: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub certificate_chain_pem: Option<String>,
    pub expires_at: i64,
    pub is_temporary: bool,
    pub certificate_id: String,
}

/// Configuration data structure for Gateway use
#[derive(Debug, Clone)]
pub struct ConfigurationData {
    pub config_type: String,
    pub config_version: String,
    pub config_data: String,
    pub updated_at: i64,
    pub checksum: String,
}