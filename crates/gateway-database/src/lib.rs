//! Database Manager

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DatabaseConfig {
    pub enabled: bool,
    pub backend: String,
    pub url: String,
    pub pool_size: u32,
    pub timeout: Duration,
    pub migrations_path: String,
    pub ssl_mode: String,
}

pub struct DatabaseManager {
    config: Option<DatabaseConfig>,
}

impl DatabaseManager {
    pub async fn new(_config: &DatabaseConfig) -> Result<Self, String> {
        Ok(Self {
            config: Some(_config.clone()),
        })
    }

    pub fn disabled() -> Self {
        Self { config: None }
    }

    pub async fn is_healthy(&self) -> bool {
        true
    }

    pub async fn close(&self) -> Result<(), String> {
        Ok(())
    }
}