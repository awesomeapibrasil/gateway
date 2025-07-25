//! Plugin Manager

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PluginConfig {
    pub enabled: bool,
    pub plugin_dir: String,
    pub plugins: HashMap<String, PluginInstanceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PluginInstanceConfig {
    pub enabled: bool,
    pub config: HashMap<String, serde_json::Value>,
}

pub struct PluginManager {
    config: PluginConfig,
}

impl PluginManager {
    pub async fn new(_config: &PluginConfig) -> Result<Self, String> {
        Ok(Self {
            config: _config.clone(),
        })
    }

    pub fn disabled() -> Self {
        Self {
            config: PluginConfig {
                enabled: false,
                plugin_dir: String::new(),
                plugins: HashMap::new(),
            },
        }
    }

    pub async fn start(&self) -> Result<(), String> {
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), String> {
        Ok(())
    }

    pub async fn is_healthy(&self) -> bool {
        true
    }

    pub async fn update_config(&self, _config: &PluginConfig) -> Result<(), String> {
        Ok(())
    }
}