//! Database Manager

use serde::{Deserialize, Serialize};
use sqlx::AnyPool;
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

#[allow(dead_code)]
pub struct DatabaseManager {
    config: Option<DatabaseConfig>,
    pool: Option<AnyPool>,
}

impl DatabaseManager {
    pub async fn new(config: &DatabaseConfig) -> Result<Self, String> {
        if !config.enabled {
            return Ok(Self {
                config: Some(config.clone()),
                pool: None,
            });
        }

        // Create database connection pool
        let pool = AnyPool::connect(&config.url)
            .await
            .map_err(|e| format!("Failed to connect to database: {e}"))?;

        // Run migrations if migrations_path is provided
        if !config.migrations_path.is_empty() {
            sqlx::migrate::Migrator::new(std::path::Path::new(&config.migrations_path))
                .await
                .map_err(|e| format!("Failed to load migrations: {e}"))?
                .run(&pool)
                .await
                .map_err(|e| format!("Failed to run migrations: {e}"))?;
        }

        Ok(Self {
            config: Some(config.clone()),
            pool: Some(pool),
        })
    }

    pub fn disabled() -> Self {
        Self {
            config: None,
            pool: None,
        }
    }

    pub async fn is_healthy(&self) -> bool {
        if let Some(pool) = &self.pool {
            sqlx::query("SELECT 1").execute(pool).await.is_ok()
        } else {
            true // If disabled, consider it healthy
        }
    }

    pub fn get_pool(&self) -> Option<&AnyPool> {
        self.pool.as_ref()
    }

    pub async fn close(&self) -> Result<(), String> {
        if let Some(pool) = &self.pool {
            pool.close().await;
        }
        Ok(())
    }
}
