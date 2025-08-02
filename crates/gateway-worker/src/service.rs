//! Worker Service Implementation
//!
//! Main service coordinator that manages all worker components.

use crate::{
    certificate_manager::CertificateManager,
    config_manager::ConfigManager,
    grpc_server::GrpcServer,
    job_queue::JobQueue,
    log_processor::LogProcessor,
    WorkerConfig,
};
use anyhow::Result;
use std::sync::Arc;
use tracing::{error, info};

/// Worker Service that coordinates all background tasks
pub struct WorkerService {
    config: WorkerConfig,
    grpc_server: Arc<GrpcServer>,
    certificate_manager: Arc<CertificateManager>,
    config_manager: Arc<ConfigManager>,
    log_processor: Arc<LogProcessor>,
    job_queue: Arc<JobQueue>,
}

impl WorkerService {
    /// Create a new worker service instance
    pub async fn new(config: WorkerConfig) -> Result<Self> {
        info!("Initializing Worker Service components");

        // Initialize job queue
        let job_queue = Arc::new(JobQueue::new(&config.redis).await?);

        // Initialize certificate manager
        let certificate_manager = Arc::new(CertificateManager::new(&config.certificate).await?);

        // Initialize configuration manager
        let config_manager = Arc::new(ConfigManager::new(&config.database).await?);

        // Initialize log processor
        let log_processor = Arc::new(LogProcessor::new(&config.database, &config.redis).await?);

        // Initialize gRPC server
        let grpc_server = Arc::new(GrpcServer::new(
            &config.grpc,
            certificate_manager.clone(),
            config_manager.clone(),
            log_processor.clone(),
        )?);

        Ok(Self {
            config,
            grpc_server,
            certificate_manager,
            config_manager,
            log_processor,
            job_queue,
        })
    }

    /// Run the worker service
    pub async fn run(self) -> Result<()> {
        info!("Starting Worker Service");

        // Start background tasks
        let mut tasks = Vec::new();

        // Start gRPC server
        let grpc_handle = {
            let server = self.grpc_server.clone();
            tokio::spawn(async move {
                if let Err(e) = server.serve().await {
                    error!("gRPC server error: {}", e);
                }
            })
        };
        tasks.push(grpc_handle);

        // Start certificate renewal background task
        let cert_handle = {
            let cert_manager = self.certificate_manager.clone();
            let renewal_interval = self.config.certificate.renewal_check_interval;
            tokio::spawn(async move {
                cert_manager.start_renewal_background_task(renewal_interval).await;
            })
        };
        tasks.push(cert_handle);

        // Start job queue processor
        let job_handle = {
            let job_queue = self.job_queue.clone();
            tokio::spawn(async move {
                if let Err(e) = job_queue.start_processing().await {
                    error!("Job queue processing error: {}", e);
                }
            })
        };
        tasks.push(job_handle);

        // Start log processing background task
        let log_handle = {
            let log_processor = self.log_processor.clone();
            tokio::spawn(async move {
                if let Err(e) = log_processor.start_background_processing().await {
                    error!("Log processing error: {}", e);
                }
            })
        };
        tasks.push(log_handle);

        info!("Worker Service started successfully");

        // Wait for any task to complete (which should not happen in normal operation)
        let (result, _index, _remaining) = futures::future::select_all(tasks).await;
        if let Err(e) = result {
            error!("Worker service task failed: {:?}", e);
        }

        info!("Worker Service shutting down");
        Ok(())
    }
}