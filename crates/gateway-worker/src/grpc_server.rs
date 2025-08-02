//! gRPC Server Implementation
//!
//! Implements the Gateway-Worker gRPC communication service.

use crate::{certificate_manager::CertificateManager, config_manager::ConfigManager, log_processor::LogProcessor, GrpcConfig};
use anyhow::Result;
use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{error, info};

// Include generated protobuf types
pub mod proto {
    tonic::include_proto!("gateway_worker");
}

use proto::{
    gateway_worker_service_server::{GatewayWorkerService, GatewayWorkerServiceServer},
    *,
};

/// gRPC Server implementation for Gateway-Worker communication
pub struct GrpcServer {
    config: GrpcConfig,
    service_impl: Arc<GatewayWorkerServiceImpl>,
}

/// Implementation of the GatewayWorkerService
#[derive(Clone)]
pub struct GatewayWorkerServiceImpl {
    certificate_manager: Arc<CertificateManager>,
    config_manager: Arc<ConfigManager>,
    log_processor: Arc<LogProcessor>,
}

impl GrpcServer {
    pub fn new(
        config: &GrpcConfig,
        certificate_manager: Arc<CertificateManager>,
        config_manager: Arc<ConfigManager>,
        log_processor: Arc<LogProcessor>,
    ) -> Result<Self> {
        let service_impl = Arc::new(GatewayWorkerServiceImpl {
            certificate_manager,
            config_manager,
            log_processor,
        });

        Ok(Self {
            config: config.clone(),
            service_impl,
        })
    }

    pub async fn serve(&self) -> Result<()> {
        let addr = self.config.listen_address.parse()?;
        info!("Starting gRPC server on {}", addr);

        let service = GatewayWorkerServiceServer::new(self.service_impl.as_ref().clone());

        // TODO: Add TLS configuration when cert/key paths are provided
        Server::builder()
            .add_service(service)
            .serve(addr)
            .await?;

        Ok(())
    }
}

#[tonic::async_trait]
impl GatewayWorkerService for GatewayWorkerServiceImpl {
    async fn health_check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        let req = request.into_inner();
        info!("Health check request for service: {}", req.service);

        let response = HealthCheckResponse {
            status: health_check_response::ServingStatus::Serving as i32,
        };

        Ok(Response::new(response))
    }

    async fn get_certificate(
        &self,
        request: Request<CertificateRequest>,
    ) -> Result<Response<CertificateResponse>, Status> {
        let req = request.into_inner();
        info!("Certificate request for domain: {}", req.domain);

        match self.certificate_manager.get_certificate(&req.domain, &req.certificate_type).await {
            Ok(cert) => {
                let response = CertificateResponse {
                    domain: cert.domain,
                    certificate_pem: cert.certificate_pem,
                    private_key_pem: cert.private_key_pem,
                    certificate_chain_pem: cert.certificate_chain_pem.unwrap_or_default(),
                    expires_at: cert.expires_at,
                    is_temporary: cert.is_temporary,
                    certificate_id: cert.certificate_id,
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                error!("Failed to get certificate for domain {}: {}", req.domain, e);
                Err(Status::internal(format!("Certificate retrieval failed: {}", e)))
            }
        }
    }

    async fn update_certificate(
        &self,
        request: Request<UpdateCertificateRequest>,
    ) -> Result<Response<UpdateCertificateResponse>, Status> {
        let req = request.into_inner();
        info!("Certificate update request for domain: {}", req.domain);

        match self.certificate_manager.update_certificate(&req).await {
            Ok(cert_id) => {
                let response = UpdateCertificateResponse {
                    success: true,
                    message: "Certificate updated successfully".to_string(),
                    certificate_id: cert_id,
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                error!("Failed to update certificate for domain {}: {}", req.domain, e);
                let response = UpdateCertificateResponse {
                    success: false,
                    message: format!("Certificate update failed: {}", e),
                    certificate_id: String::new(),
                };
                Ok(Response::new(response))
            }
        }
    }

    type WatchCertificateUpdatesStream = 
        tokio_stream::wrappers::ReceiverStream<Result<CertificateUpdate, Status>>;

    async fn watch_certificate_updates(
        &self,
        request: Request<CertificateWatchRequest>,
    ) -> Result<Response<Self::WatchCertificateUpdatesStream>, Status> {
        let req = request.into_inner();
        info!("Certificate watch request from gateway: {}", req.gateway_id);

        let (tx, rx) = tokio::sync::mpsc::channel(100);
        
        // Start watching certificate updates
        let cert_manager = self.certificate_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = cert_manager.watch_updates(req, tx).await {
                error!("Certificate watch error: {}", e);
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(stream))
    }

    async fn get_configuration(
        &self,
        request: Request<ConfigurationRequest>,
    ) -> Result<Response<ConfigurationResponse>, Status> {
        let req = request.into_inner();
        info!("Configuration request for gateway: {}, type: {}", req.gateway_id, req.config_type);

        match self.config_manager.get_configuration(&req).await {
            Ok(config) => {
                let response = ConfigurationResponse {
                    config_type: config.config_type,
                    config_version: config.config_version,
                    config_data: config.config_data,
                    updated_at: config.updated_at,
                    checksum: config.checksum,
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                error!("Failed to get configuration: {}", e);
                Err(Status::internal(format!("Configuration retrieval failed: {}", e)))
            }
        }
    }

    async fn update_configuration(
        &self,
        request: Request<UpdateConfigurationRequest>,
    ) -> Result<Response<UpdateConfigurationResponse>, Status> {
        let req = request.into_inner();
        info!("Configuration update request for type: {}", req.config_type);

        match self.config_manager.update_configuration(&req).await {
            Ok(result) => {
                let response = UpdateConfigurationResponse {
                    success: result.success,
                    message: result.message,
                    config_version: result.config_version,
                    validation_errors: result.validation_errors,
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                error!("Failed to update configuration: {}", e);
                let response = UpdateConfigurationResponse {
                    success: false,
                    message: format!("Configuration update failed: {}", e),
                    config_version: String::new(),
                    validation_errors: vec![e.to_string()],
                };
                Ok(Response::new(response))
            }
        }
    }

    type WatchConfigurationUpdatesStream = 
        tokio_stream::wrappers::ReceiverStream<Result<ConfigurationUpdate, Status>>;

    async fn watch_configuration_updates(
        &self,
        request: Request<ConfigurationWatchRequest>,
    ) -> Result<Response<Self::WatchConfigurationUpdatesStream>, Status> {
        let req = request.into_inner();
        info!("Configuration watch request from gateway: {}", req.gateway_id);

        let (tx, rx) = tokio::sync::mpsc::channel(100);
        
        // Start watching configuration updates
        let config_manager = self.config_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = config_manager.watch_updates(req, tx).await {
                error!("Configuration watch error: {}", e);
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(stream))
    }

    async fn send_logs(
        &self,
        request: Request<tonic::Streaming<LogEntry>>,
    ) -> Result<Response<LogProcessingResponse>, Status> {
        let mut stream = request.into_inner();
        let mut processed_count = 0;
        let mut error_count = 0;

        while let Some(log_entry) = stream.message().await? {
            match self.log_processor.process_log_entry(log_entry).await {
                Ok(_) => processed_count += 1,
                Err(e) => {
                    error!("Failed to process log entry: {}", e);
                    error_count += 1;
                }
            }
        }

        let response = LogProcessingResponse {
            success: error_count == 0,
            message: if error_count == 0 {
                "All logs processed successfully".to_string()
            } else {
                format!("Processed {} logs with {} errors", processed_count, error_count)
            },
            processed_count,
            error_count,
        };

        Ok(Response::new(response))
    }

    async fn get_metrics(
        &self,
        request: Request<MetricsRequest>,
    ) -> Result<Response<MetricsResponse>, Status> {
        let req = request.into_inner();
        info!("Metrics request from gateway: {}", req.gateway_id);

        match self.log_processor.get_metrics(&req).await {
            Ok(metrics) => {
                let response = MetricsResponse {
                    metrics,
                    timestamp: chrono::Utc::now().timestamp(),
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                error!("Failed to get metrics: {}", e);
                Err(Status::internal(format!("Metrics retrieval failed: {}", e)))
            }
        }
    }
}