use clap::Parser;
use gateway_core::{Gateway, GatewayConfig};
use std::process;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "gateway")]
#[command(about = "A high-performance API Gateway and Ingress Controller built with Pingora")]
#[command(version = "0.1.0")]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config/gateway.yaml")]
    config: String,

    /// Enable debug mode
    #[arg(short, long)]
    debug: bool,

    /// Number of worker threads
    #[arg(short, long, default_value = "4")]
    workers: usize,

    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0:8080")]
    bind: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize tracing
    let level = if args.debug {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .compact()
        .init();

    info!("Starting Pingora-based API Gateway v0.1.0");

    // Load configuration
    let config = match GatewayConfig::from_file(&args.config) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration from {}: {}", args.config, e);
            process::exit(1);
        }
    };

    // Override config with CLI args
    let mut config = config;
    config.server.bind_address = args.bind.clone();
    config.server.worker_threads = args.workers;
    config.server.debug = args.debug;

    info!("Configuration loaded successfully");
    info!("Binding to: {}", config.server.bind_address);
    info!("Worker threads: {}", config.server.worker_threads);

    // Initialize and start the gateway
    let gateway = Gateway::new(config).await?;

    info!("Gateway initialized, starting services...");

    if let Err(e) = gateway.run().await {
        error!("Gateway error: {}", e);
        process::exit(1);
    }

    Ok(())
}
