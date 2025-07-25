//! Authentication and Authorization Manager

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthConfig {
    pub enabled: bool,
    pub jwt_secret: String,
    pub jwt_expiry: Duration,
    pub providers: HashMap<String, AuthProviderConfig>,
    pub require_auth: bool,
    pub public_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthProviderConfig {
    pub provider_type: String,
    pub config: HashMap<String, String>,
}

pub struct AuthManager {
    config: AuthConfig,
}

impl AuthManager {
    pub async fn new(_config: &AuthConfig, _database: std::sync::Arc<gateway_database::DatabaseManager>) -> Result<Self, String> {
        Ok(Self {
            config: _config.clone(),
        })
    }

    pub async fn is_healthy(&self) -> bool {
        true
    }

    pub async fn update_config(&self, _config: &AuthConfig) -> Result<(), String> {
        Ok(())
    }
}