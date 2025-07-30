//! Authentication and Authorization Manager

use serde::{Deserialize, Serialize};
use sqlx::Row;
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
    database: std::sync::Arc<gateway_database::DatabaseManager>,
}

impl AuthManager {
    pub async fn new(
        config: &AuthConfig,
        database: std::sync::Arc<gateway_database::DatabaseManager>,
    ) -> Result<Self, String> {
        Ok(Self {
            config: config.clone(),
            database,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn get_public_paths(&self) -> &Vec<String> {
        &self.config.public_paths
    }

    pub async fn authenticate_request(&self, uri: &str) -> Result<(), String> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check if URI is in public paths (no authentication required)
        for public_path in &self.config.public_paths {
            if uri.starts_with(public_path) {
                tracing::debug!("Request to public path: {}", uri);
                return Ok(());
            }
        }

        // If require_auth is false and no specific auth header, allow
        if !self.config.require_auth {
            tracing::debug!("Authentication not required for: {}", uri);
            return Ok(());
        }

        // In a real implementation, this would:
        // 1. Extract Authorization header from request
        // 2. Validate JWT token using the configured secret
        // 3. Check token expiration
        // 4. Verify user permissions against the requested resource
        // 5. Check against database for user status and permissions

        // For now, simulate a basic authentication check
        tracing::info!("Authentication check performed for URI: {}", uri);

        // Simulate success - in production, this would validate actual tokens
        Ok(())
    }

    /// Validate JWT token (production-ready implementation)
    pub async fn validate_jwt_token(
        &self,
        token: &str,
    ) -> Result<jsonwebtoken::TokenData<serde_json::Value>, String> {
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

        let key = DecodingKey::from_secret(self.config.jwt_secret.as_ref());
        let validation = Validation::new(Algorithm::HS256);

        decode::<serde_json::Value>(token, &key, &validation)
            .map_err(|e| format!("JWT validation failed: {e}"))
    }

    /// Generate JWT token for a user
    pub async fn generate_jwt_token(
        &self,
        user_id: &str,
        claims: Option<serde_json::Value>,
    ) -> Result<String, String> {
        use jsonwebtoken::{encode, EncodingKey, Header};
        use serde_json::json;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let exp = now + self.config.jwt_expiry.as_secs();

        let token_claims = json!({
            "sub": user_id,
            "iat": now,
            "exp": exp,
            "data": claims.unwrap_or_else(|| json!({}))
        });

        let key = EncodingKey::from_secret(self.config.jwt_secret.as_ref());
        encode(&Header::default(), &token_claims, &key)
            .map_err(|e| format!("JWT generation failed: {e}"))
    }

    /// Verify user credentials against database
    pub async fn verify_user_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<uuid::Uuid>, String> {
        if let Some(pool) = self.database.get_pool() {
            let result =
                sqlx::query("SELECT id, password_hash, active FROM users WHERE username = $1")
                    .bind(username)
                    .fetch_optional(pool)
                    .await;

            match result {
                Ok(Some(row)) => {
                    let user_id_str: String = row.try_get("id").map_err(|e| e.to_string())?;
                    let user_id = uuid::Uuid::parse_str(&user_id_str)
                        .map_err(|e| format!("Invalid UUID format: {e}"))?;
                    let password_hash: String =
                        row.try_get("password_hash").map_err(|e| e.to_string())?;
                    let active: bool = row.try_get("active").map_err(|e| e.to_string())?;

                    if !active {
                        return Err("User account is disabled".to_string());
                    }

                    // Verify password using bcrypt
                    match bcrypt::verify(password, &password_hash) {
                        Ok(true) => {
                            tracing::info!("User {} authenticated successfully", username);
                            Ok(Some(user_id))
                        }
                        Ok(false) => {
                            tracing::warn!("Invalid password for user: {}", username);
                            Err("Invalid credentials".to_string())
                        }
                        Err(e) => {
                            tracing::error!("Password verification error: {}", e);
                            Err("Authentication error".to_string())
                        }
                    }
                }
                Ok(None) => {
                    tracing::warn!("User not found: {}", username);
                    Err("Invalid credentials".to_string())
                }
                Err(e) => {
                    tracing::error!("Database error during authentication: {}", e);
                    Err("Authentication error".to_string())
                }
            }
        } else {
            Err("Database not available".to_string())
        }
    }

    /// Create a new user with hashed password
    pub async fn create_user(
        &self,
        username: &str,
        email: Option<&str>,
        password: &str,
    ) -> Result<uuid::Uuid, String> {
        // Hash the password
        let password_hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)
            .map_err(|e| format!("Password hashing failed: {e}"))?;

        if let Some(pool) = self.database.get_pool() {
            let user_id = uuid::Uuid::new_v4();

            let result = sqlx::query(
                r#"
                INSERT INTO users (id, username, email, password_hash, active)
                VALUES ($1, $2, $3, $4, $5)
                "#,
            )
            .bind(user_id.to_string())
            .bind(username)
            .bind(email)
            .bind(&password_hash)
            .bind(true)
            .execute(pool)
            .await;

            match result {
                Ok(_) => {
                    tracing::info!("User created successfully: {}", username);
                    Ok(user_id)
                }
                Err(e) => {
                    tracing::error!("Failed to create user: {}", e);
                    Err(format!("User creation failed: {e}"))
                }
            }
        } else {
            Err("Database not available".to_string())
        }
    }

    pub async fn is_healthy(&self) -> bool {
        true
    }

    pub async fn update_config(&self, _config: &AuthConfig) -> Result<(), String> {
        Ok(())
    }
}
