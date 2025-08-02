//! Configuration Manager
//!
//! Handles configuration management including WAF rules, routing configuration,
//! and real-time updates to Gateway instances.

use crate::{grpc_server::proto::*, DatabaseConfig};
use anyhow::Result;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub struct ConfigurationData {
    pub config_type: String,
    pub config_version: String,
    pub config_data: String,
    pub updated_at: i64,
    pub checksum: String,
}

#[derive(Debug, Clone)]
pub struct ConfigUpdateResult {
    pub success: bool,
    pub message: String,
    pub config_version: String,
    pub validation_errors: Vec<String>,
}

/// Configuration Manager handles all configuration-related operations
pub struct ConfigManager {
    config: DatabaseConfig,
    // In a real implementation, this would be replaced with proper database storage
    configurations: tokio::sync::RwLock<HashMap<String, ConfigurationData>>,
}

impl ConfigManager {
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        info!("Initializing Configuration Manager");
        
        let mut configurations = HashMap::new();
        
        // Initialize with default configurations
        configurations.insert("waf".to_string(), ConfigurationData {
            config_type: "waf".to_string(),
            config_version: "1.0.0".to_string(),
            config_data: Self::default_waf_config(),
            updated_at: chrono::Utc::now().timestamp(),
            checksum: "default_waf_checksum".to_string(),
        });
        
        configurations.insert("routing".to_string(), ConfigurationData {
            config_type: "routing".to_string(),
            config_version: "1.0.0".to_string(),
            config_data: Self::default_routing_config(),
            updated_at: chrono::Utc::now().timestamp(),
            checksum: "default_routing_checksum".to_string(),
        });
        
        Ok(Self {
            config: config.clone(),
            configurations: tokio::sync::RwLock::new(configurations),
        })
    }

    pub async fn get_configuration(&self, request: &ConfigurationRequest) -> Result<ConfigurationData> {
        info!("Getting configuration for gateway: {}, type: {}", request.gateway_id, request.config_type);
        
        let configurations = self.configurations.read().await;
        
        if let Some(config) = configurations.get(&request.config_type) {
            // If specific version requested, validate it
            if !request.config_version.is_empty() && request.config_version != config.config_version {
                warn!("Requested version {} not found for config type {}, returning latest", 
                      request.config_version, request.config_type);
            }
            
            Ok(config.clone())
        } else {
            Err(anyhow::anyhow!("Configuration not found for type: {}", request.config_type))
        }
    }

    pub async fn update_configuration(&self, request: &UpdateConfigurationRequest) -> Result<ConfigUpdateResult> {
        info!("Updating configuration for type: {}", request.config_type);
        
        // Validate configuration
        let validation_result = self.validate_configuration(&request.config_type, &request.config_data).await?;
        
        if !validation_result.is_valid {
            return Ok(ConfigUpdateResult {
                success: false,
                message: "Configuration validation failed".to_string(),
                config_version: String::new(),
                validation_errors: validation_result.errors,
            });
        }

        if request.validate_only {
            return Ok(ConfigUpdateResult {
                success: true,
                message: "Configuration validation passed".to_string(),
                config_version: String::new(),
                validation_errors: vec![],
            });
        }

        // Update configuration
        let new_version = format!("{}.{}", 
                                 chrono::Utc::now().timestamp(), 
                                 uuid::Uuid::new_v4().to_string()[..8].to_string());
        
        let config_data = ConfigurationData {
            config_type: request.config_type.clone(),
            config_version: new_version.clone(),
            config_data: request.config_data.clone(),
            updated_at: chrono::Utc::now().timestamp(),
            checksum: Self::calculate_checksum(&request.config_data),
        };

        let mut configurations = self.configurations.write().await;
        configurations.insert(request.config_type.clone(), config_data);
        
        info!("Configuration updated for type: {}, new version: {}", request.config_type, new_version);
        
        Ok(ConfigUpdateResult {
            success: true,
            message: "Configuration updated successfully".to_string(),
            config_version: new_version,
            validation_errors: vec![],
        })
    }

    pub async fn watch_updates(
        &self,
        request: ConfigurationWatchRequest,
        tx: mpsc::Sender<Result<ConfigurationUpdate, tonic::Status>>,
    ) -> Result<()> {
        info!("Starting configuration watch for gateway: {}", request.gateway_id);
        
        // TODO: Implement actual configuration watching
        // For now, send a sample update
        let update = ConfigurationUpdate {
            update_type: configuration_update::UpdateType::Updated as i32,
            config_type: "waf".to_string(),
            configuration: None,
            message: "Configuration watch started".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
        };

        if let Err(e) = tx.send(Ok(update)).await {
            error!("Failed to send configuration update: {}", e);
        }

        Ok(())
    }

    async fn validate_configuration(&self, config_type: &str, config_data: &str) -> Result<ValidationResult> {
        info!("Validating configuration for type: {}", config_type);
        
        match config_type {
            "waf" => self.validate_waf_configuration(config_data).await,
            "routing" => self.validate_routing_configuration(config_data).await,
            "backend" => self.validate_backend_configuration(config_data).await,
            "security" => self.validate_security_configuration(config_data).await,
            _ => Ok(ValidationResult {
                is_valid: false,
                errors: vec![format!("Unknown configuration type: {}", config_type)],
            }),
        }
    }

    async fn validate_waf_configuration(&self, config_data: &str) -> Result<ValidationResult> {
        // TODO: Implement WAF configuration validation
        // Check ModSecurity rule syntax, OWASP CRS compatibility, etc.
        
        if config_data.trim().is_empty() {
            return Ok(ValidationResult {
                is_valid: false,
                errors: vec!["WAF configuration cannot be empty".to_string()],
            });
        }

        // Basic JSON/YAML validation
        if config_data.starts_with('{') {
            match serde_json::from_str::<serde_json::Value>(config_data) {
                Ok(_) => Ok(ValidationResult { is_valid: true, errors: vec![] }),
                Err(e) => Ok(ValidationResult {
                    is_valid: false,
                    errors: vec![format!("Invalid JSON: {}", e)],
                }),
            }
        } else {
            match serde_yaml::from_str::<serde_yaml::Value>(config_data) {
                Ok(_) => Ok(ValidationResult { is_valid: true, errors: vec![] }),
                Err(e) => Ok(ValidationResult {
                    is_valid: false,
                    errors: vec![format!("Invalid YAML: {}", e)],
                }),
            }
        }
    }

    async fn validate_routing_configuration(&self, _config_data: &str) -> Result<ValidationResult> {
        // TODO: Implement routing configuration validation
        // Check route patterns, backend references, etc.
        Ok(ValidationResult { is_valid: true, errors: vec![] })
    }

    async fn validate_backend_configuration(&self, _config_data: &str) -> Result<ValidationResult> {
        // TODO: Implement backend configuration validation
        // Check backend addresses, health check configurations, etc.
        Ok(ValidationResult { is_valid: true, errors: vec![] })
    }

    async fn validate_security_configuration(&self, _config_data: &str) -> Result<ValidationResult> {
        // TODO: Implement security configuration validation
        // Check authentication settings, authorization policies, etc.
        Ok(ValidationResult { is_valid: true, errors: vec![] })
    }

    fn default_waf_config() -> String {
        serde_json::json!({
            "enabled": true,
            "mode": "blocking",
            "rules": [
                {
                    "id": "100001",
                    "description": "SQL Injection Detection",
                    "pattern": "@detectSQLi",
                    "action": "block"
                },
                {
                    "id": "100002", 
                    "description": "XSS Detection",
                    "pattern": "@detectXSS",
                    "action": "block"
                }
            ]
        }).to_string()
    }

    fn default_routing_config() -> String {
        serde_json::json!({
            "routes": [
                {
                    "id": "default",
                    "path": "/*",
                    "method": "*",
                    "backend": "default_backend"
                }
            ],
            "backends": [
                {
                    "id": "default_backend",
                    "address": "http://localhost:3000",
                    "weight": 1,
                    "enabled": true
                }
            ]
        }).to_string()
    }

    fn calculate_checksum(data: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[derive(Debug)]
struct ValidationResult {
    is_valid: bool,
    errors: Vec<String>,
}