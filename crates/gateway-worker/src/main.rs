//! Gateway Worker Service Main Binary
//!
//! This is the main entry point for the Gateway Worker service that handles
//! background tasks as described in WORKER-PURPOSE.md.

use clap::Parser;
use gateway_worker::{init_tracing, service::WorkerService, Args, WorkerConfig};
use std::process;
use tracing::{error, info};

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Load configuration
    let config = match WorkerConfig::from_file(&args.config) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            process::exit(1);
        }
    };

    // Initialize tracing
    if let Err(e) = init_tracing(&config.logging) {
        eprintln!("Failed to initialize tracing: {}", e);
        process::exit(1);
    }

    info!("Starting Gateway Worker Service");
    info!("Configuration loaded from: {:?}", args.config);

    // Validate configuration
    if let Err(e) = config.validate() {
        error!("Configuration validation failed: {}", e);
        process::exit(1);
    }

    if args.dry_run {
        info!("Dry run mode - configuration validated successfully");
        return;
    }

    // Create and start the worker service
    let worker_service = match WorkerService::new(config).await {
        Ok(service) => service,
        Err(e) => {
            error!("Failed to create worker service: {}", e);
            process::exit(1);
        }
    };

    // Run the service
    if let Err(e) = worker_service.run().await {
        error!("Worker service failed: {}", e);
        process::exit(1);
    }

    info!("Gateway Worker Service stopped");
}