//! Gateway Worker Service
//!
//! This is the Worker service that handles background tasks for the Gateway,
//! including certificate management, configuration updates, log processing,
//! and analytics as described in WORKER-PURPOSE.md.

pub mod certificate_manager;
pub mod config_manager;
pub mod grpc_server;
pub mod job_queue;
pub mod log_processor;
pub mod service;

use anyhow::Result;
use clap::Parser;
use config::Config;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorkerConfig {
    pub server: ServerConfig,
    pub grpc: GrpcConfig,
    pub certificate: CertificateConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub bind_address: String,
    pub worker_threads: Option<usize>,
    pub max_connections: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GrpcConfig {
    pub listen_address: String,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub enable_mtls: bool,
    pub ca_cert_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CertificateConfig {
    pub acme_directory_url: String,
    pub acme_account_key_path: String,
    pub certificate_storage_path: String,
    pub renewal_check_interval: u64, // seconds
    pub renewal_before_expiry_days: u32,
    pub temporary_cert_validity_days: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub connection_timeout: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedisConfig {
    pub url: String,
    pub max_connections: u32,
    pub connection_timeout: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub output: String,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                bind_address: "0.0.0.0:8081".to_string(),
                worker_threads: Some(4),
                max_connections: Some(1000),
            },
            grpc: GrpcConfig {
                listen_address: "0.0.0.0:50051".to_string(),
                tls_cert_path: None,
                tls_key_path: None,
                enable_mtls: false,
                ca_cert_path: None,
            },
            certificate: CertificateConfig {
                acme_directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
                acme_account_key_path: "/etc/gateway/acme-account.key".to_string(),
                certificate_storage_path: "/etc/gateway/certificates".to_string(),
                renewal_check_interval: 3600, // 1 hour
                renewal_before_expiry_days: 30,
                temporary_cert_validity_days: 14,
            },
            database: DatabaseConfig {
                url: "postgresql://gateway:password@localhost/gateway_worker".to_string(),
                max_connections: 10,
                connection_timeout: 30,
            },
            redis: RedisConfig {
                url: "redis://localhost:6379".to_string(),
                max_connections: 10,
                connection_timeout: 10,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
                output: "stdout".to_string(),
            },
        }
    }
}

impl WorkerConfig {
    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let config = Config::builder()
            .add_source(config::File::from(path.clone()))
            .add_source(config::Environment::with_prefix("GATEWAY_WORKER"))
            .build()?;

        let worker_config: WorkerConfig = config.try_deserialize()?;
        Ok(worker_config)
    }

    pub fn validate(&self) -> Result<()> {
        // Validate configuration
        if self.certificate.temporary_cert_validity_days > 14 {
            warn!("Temporary certificate validity days is greater than 14, setting to 14");
        }

        if self.certificate.renewal_before_expiry_days > 90 {
            warn!("Certificate renewal before expiry days is greater than 90, this might cause frequent renewals");
        }

        info!("Worker configuration validation passed");
        Ok(())
    }
}

#[derive(Debug, Parser)]
#[command(name = "gateway-worker")]
#[command(about = "Gateway Worker Service - handles background tasks for the Gateway")]
pub struct Args {
    #[arg(short, long, default_value = "config/worker.yaml")]
    pub config: PathBuf,

    #[arg(short, long)]
    pub verbose: bool,

    #[arg(long)]
    pub dry_run: bool,
}

/// Initialize tracing based on configuration
pub fn init_tracing(config: &LoggingConfig) -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.level));

    match config.format.as_str() {
        "json" => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        _ => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer())
                .init();
        }
    }

    Ok(())
}