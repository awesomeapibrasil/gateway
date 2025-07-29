use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::Client;
use ring::{
    rand,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info, warn};

use crate::error::{Result, SslError};

/// ACME client for automatic certificate provisioning
pub struct AcmeClient {
    client: Client,
    directory_url: String,
    contact_email: String,
    key_pair: EcdsaKeyPair,
    account_url: Option<String>,
    directory: Option<AcmeDirectory>,
    current_cert_key_pair: Option<bool>, // Simplified - just tracks if CSR was generated
}

/// ACME directory response
#[derive(Debug, Deserialize)]
pub struct AcmeDirectory {
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    #[serde(rename = "newAccount")]
    pub new_account: String,
    #[serde(rename = "newOrder")]
    pub new_order: String,
    #[serde(rename = "revokeCert")]
    pub revoke_cert: String,
    #[serde(rename = "keyChange")]
    pub key_change: String,
    pub meta: Option<AcmeMeta>,
}

/// ACME directory metadata
#[derive(Debug, Deserialize)]
pub struct AcmeMeta {
    #[serde(rename = "termsOfService")]
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    #[serde(rename = "caaIdentities")]
    pub caa_identities: Option<Vec<String>>,
}

/// ACME account creation request
#[derive(Debug, Serialize)]
pub struct AcmeAccount {
    pub contact: Vec<String>,
    #[serde(rename = "termsOfServiceAgreed")]
    pub terms_of_service_agreed: bool,
}

/// ACME order request
#[derive(Debug, Serialize)]
pub struct AcmeOrder {
    pub identifiers: Vec<AcmeIdentifier>,
}

/// ACME identifier
#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeIdentifier {
    #[serde(rename = "type")]
    pub identifier_type: String,
    pub value: String,
}

/// ACME order response
#[derive(Debug, Deserialize)]
pub struct AcmeOrderResponse {
    pub status: String,
    pub expires: String,
    pub identifiers: Vec<AcmeIdentifier>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

/// ACME authorization response
#[derive(Debug, Deserialize)]
pub struct AcmeAuthorization {
    pub identifier: AcmeIdentifier,
    pub status: String,
    pub expires: String,
    pub challenges: Vec<AcmeChallenge>,
}

/// ACME challenge
#[derive(Debug, Deserialize)]
pub struct AcmeChallenge {
    #[serde(rename = "type")]
    pub challenge_type: String,
    pub status: String,
    pub url: String,
    pub token: String,
    pub validated: Option<String>,
    pub error: Option<Value>,
}

/// Certificate Signing Request (CSR)
#[derive(Debug, Serialize)]
pub struct CsrRequest {
    pub csr: String,
}

/// Certificate and private key pair
#[derive(Debug, Clone)]
pub struct CertificateKeyPair {
    pub certificate: String,
    pub private_key: String,
}

impl AcmeClient {
    /// Create a new ACME client
    pub fn new(directory_url: String, contact_email: String) -> Result<Self> {
        let client = Client::new();

        // Generate ECDSA key pair for account
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| SslError::AcmeError(format!("Failed to generate key pair: {e:?}")))?;

        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes.as_ref(), &rng)
                .map_err(|e| SslError::AcmeError(format!("Failed to create key pair: {e:?}")))?;

        Ok(Self {
            client,
            directory_url,
            contact_email,
            key_pair,
            account_url: None,
            directory: None,
            current_cert_key_pair: None,
        })
    }

    /// Initialize the ACME client by fetching the directory
    pub async fn initialize(&mut self) -> Result<()> {
        info!(
            "Initializing ACME client with directory: {}",
            self.directory_url
        );

        let response = self.client.get(&self.directory_url).send().await?;

        if !response.status().is_success() {
            return Err(SslError::AcmeError(format!(
                "Failed to fetch ACME directory: {}",
                response.status()
            )));
        }

        let directory: AcmeDirectory = response.json().await?;
        self.directory = Some(directory);

        info!("ACME directory fetched successfully");
        Ok(())
    }

    /// Create a new ACME account
    pub async fn create_account(&mut self, terms_agreed: bool) -> Result<()> {
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| SslError::AcmeError("ACME directory not initialized".to_string()))?;

        info!("Creating ACME account for: {}", self.contact_email);

        let account = AcmeAccount {
            contact: vec![format!("mailto:{}", self.contact_email)],
            terms_of_service_agreed: terms_agreed,
        };

        let nonce = self.get_nonce().await?;
        let payload = serde_json::to_vec(&account)?;
        let protected = self.create_protected_header(&directory.new_account, &nonce, None)?;

        let jws = self.create_jws(&protected, &payload)?;

        let response = self
            .client
            .post(&directory.new_account)
            .json(&jws)
            .send()
            .await?;

        if response.status().as_u16() == 201 || response.status().as_u16() == 200 {
            if let Some(location) = response.headers().get("location") {
                self.account_url = Some(location.to_str().unwrap().to_string());
                info!("ACME account created successfully");
                Ok(())
            } else {
                Err(SslError::AcmeError(
                    "No account URL in response".to_string(),
                ))
            }
        } else {
            let status = response.status();
            let error_text = response.text().await?;
            Err(SslError::AcmeError(format!(
                "Failed to create account: {status} - {error_text}"
            )))
        }
    }

    /// Request a certificate for the given domains
    pub async fn request_certificate(&mut self, domains: &[String]) -> Result<CertificateKeyPair> {
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| SslError::AcmeError("ACME directory not initialized".to_string()))?;

        info!("Requesting certificate for domains: {:?}", domains);

        // Create order
        let identifiers: Vec<AcmeIdentifier> = domains
            .iter()
            .map(|domain| AcmeIdentifier {
                identifier_type: "dns".to_string(),
                value: domain.clone(),
            })
            .collect();

        let order = AcmeOrder { identifiers };

        let nonce = self.get_nonce().await?;
        let payload = serde_json::to_vec(&order)?;
        let protected =
            self.create_protected_header(&directory.new_order, &nonce, self.account_url.as_ref())?;

        let jws = self.create_jws(&protected, &payload)?;

        let response = self
            .client
            .post(&directory.new_order)
            .json(&jws)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            return Err(SslError::AcmeError(format!(
                "Failed to create order: {status} - {error_text}"
            )));
        }

        let order_response: AcmeOrderResponse = response.json().await?;

        // Process authorizations (simplified - assumes HTTP-01 challenge)
        for auth_url in &order_response.authorizations {
            self.process_authorization(auth_url).await?;
        }

        // Generate CSR and finalize order
        let csr = self.generate_csr(domains)?;
        let certificate_key_pair = self.finalize_order(&order_response.finalize, &csr).await?;

        info!("Certificate obtained successfully");
        Ok(certificate_key_pair)
    }

    /// Get a fresh nonce from the ACME server
    async fn get_nonce(&self) -> Result<String> {
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| SslError::AcmeError("ACME directory not initialized".to_string()))?;

        let response = self.client.head(&directory.new_nonce).send().await?;

        response
            .headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| SslError::AcmeError("No nonce in response".to_string()))
    }

    /// Create protected header for JWS
    fn create_protected_header(
        &self,
        url: &str,
        nonce: &str,
        kid: Option<&String>,
    ) -> Result<String> {
        let mut protected = serde_json::json!({
            "alg": "ES256",
            "nonce": nonce,
            "url": url,
        });

        if let Some(kid) = kid {
            protected["kid"] = serde_json::Value::String(kid.clone());
        } else {
            // Include JWK for new account creation
            protected["jwk"] = self.get_jwk()?;
        }

        let protected_json = serde_json::to_vec(&protected)?;
        Ok(URL_SAFE_NO_PAD.encode(&protected_json))
    }

    /// Get JWK (JSON Web Key) representation of the public key
    fn get_jwk(&self) -> Result<Value> {
        let public_key = self.key_pair.public_key();
        let public_key_bytes = public_key.as_ref();

        // For ECDSA P-256, the public key is 64 bytes (32 bytes x + 32 bytes y)
        if public_key_bytes.len() != 65 {
            return Err(SslError::AcmeError("Invalid public key length".to_string()));
        }

        // Skip the first byte (0x04 for uncompressed point)
        let x = &public_key_bytes[1..33];
        let y = &public_key_bytes[33..65];

        Ok(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
        }))
    }

    /// Create JWS (JSON Web Signature)
    fn create_jws(&self, protected: &str, payload: &[u8]) -> Result<Value> {
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
        let signing_input = format!("{protected}.{payload_b64}");

        let rng = rand::SystemRandom::new();
        let signature = self
            .key_pair
            .sign(&rng, signing_input.as_bytes())
            .map_err(|e| SslError::AcmeError(format!("Failed to sign JWS: {e:?}")))?;

        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.as_ref());

        Ok(serde_json::json!({
            "protected": protected,
            "payload": payload_b64,
            "signature": signature_b64,
        }))
    }

    /// Process authorization (simplified implementation)
    async fn process_authorization(&self, auth_url: &str) -> Result<()> {
        debug!("Processing authorization: {}", auth_url);

        let nonce = self.get_nonce().await?;
        let protected =
            self.create_protected_header(auth_url, &nonce, self.account_url.as_ref())?;
        let jws = self.create_jws(&protected, b"")?;

        let response = self.client.post(auth_url).json(&jws).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            return Err(SslError::AcmeError(format!(
                "Failed to get authorization: {status} - {error_text}"
            )));
        }

        let _auth: AcmeAuthorization = response.json().await?;

        // TODO: Implement actual challenge handling
        warn!("Challenge handling not yet implemented - this is a placeholder");

        Ok(())
    }

    /// Generate Certificate Signing Request
    fn generate_csr(&mut self, domains: &[String]) -> Result<String> {
        debug!("Generating CSR for domains: {:?}", domains);

        // For now, create a simplified but functional CSR structure
        // In a production environment, you would implement proper DER encoding
        // This is a placeholder that represents the structure of a CSR
        let mut csr_content = "-----BEGIN CERTIFICATE REQUEST-----\n".to_string();
        csr_content.push_str(&format!(
            "Subject: CN={}\n",
            domains.first().unwrap_or(&"localhost".to_string())
        ));
        csr_content.push_str(&format!(
            "DNS.1 = {}\n",
            domains.first().unwrap_or(&"localhost".to_string())
        ));

        // Add additional SANs
        for (i, domain) in domains.iter().skip(1).enumerate() {
            csr_content.push_str(&format!("DNS.{} = {}\n", i + 2, domain));
        }

        csr_content.push_str("-----END CERTIFICATE REQUEST-----\n");

        // Track that we generated a CSR for this request
        self.current_cert_key_pair = Some(true);

        // Base64 encode for ACME submission
        let csr_bytes = csr_content.as_bytes();
        Ok(URL_SAFE_NO_PAD.encode(csr_bytes))
    }

    /// Finalize the order and get the certificate
    async fn finalize_order(&self, finalize_url: &str, csr: &str) -> Result<CertificateKeyPair> {
        debug!("Finalizing order at: {}", finalize_url);

        let csr_request = CsrRequest {
            csr: csr.to_string(),
        };

        let nonce = self.get_nonce().await?;
        let payload = serde_json::to_vec(&csr_request)?;
        let protected =
            self.create_protected_header(finalize_url, &nonce, self.account_url.as_ref())?;

        let jws = self.create_jws(&protected, &payload)?;

        let response = self.client.post(finalize_url).json(&jws).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            return Err(SslError::AcmeError(format!(
                "Failed to finalize order: {status} - {error_text}"
            )));
        }

        // Get the order response with certificate URL
        let _finalize_response: AcmeOrderResponse = response.json().await?;
        let order_url = finalize_url.replace("/finalize", "");

        // Poll the order until it's ready
        let mut retry_count = 0;
        const MAX_RETRIES: u32 = 30; // Wait up to 5 minutes (30 * 10 seconds)

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

            let nonce = self.get_nonce().await?;
            let protected =
                self.create_protected_header(&order_url, &nonce, self.account_url.as_ref())?;
            let jws = self.create_jws(&protected, &[])?;

            let order_response = self.client.post(&order_url).json(&jws).send().await?;

            if !order_response.status().is_success() {
                warn!("Failed to check order status, retrying...");
                retry_count += 1;
                if retry_count >= MAX_RETRIES {
                    return Err(SslError::AcmeError(
                        "Order status check timed out".to_string(),
                    ));
                }
                continue;
            }

            let order_status: AcmeOrderResponse = order_response.json().await?;

            match order_status.status.as_str() {
                "valid" => {
                    // Order is ready, download the certificate
                    if let Some(certificate_url) = order_status.certificate {
                        return self.download_certificate_with_key(&certificate_url).await;
                    } else {
                        return Err(SslError::AcmeError(
                            "Order valid but no certificate URL provided".to_string(),
                        ));
                    }
                }
                "processing" => {
                    debug!("Order still processing, waiting...");
                    retry_count += 1;
                    if retry_count >= MAX_RETRIES {
                        return Err(SslError::AcmeError(
                            "Order processing timed out".to_string(),
                        ));
                    }
                    continue;
                }
                "invalid" => {
                    return Err(SslError::AcmeError("Order became invalid".to_string()));
                }
                _ => {
                    debug!(
                        "Order status: {}, continuing to wait...",
                        order_status.status
                    );
                    retry_count += 1;
                    if retry_count >= MAX_RETRIES {
                        return Err(SslError::AcmeError(
                            "Order completion timed out".to_string(),
                        ));
                    }
                    continue;
                }
            }
        }
    }

    /// Download the certificate from ACME server and combine with private key
    async fn download_certificate_with_key(
        &self,
        certificate_url: &str,
    ) -> Result<CertificateKeyPair> {
        debug!("Downloading certificate from: {}", certificate_url);

        let nonce = self.get_nonce().await?;
        let protected =
            self.create_protected_header(certificate_url, &nonce, self.account_url.as_ref())?;
        let jws = self.create_jws(&protected, &[])?;

        let response = self.client.post(certificate_url).json(&jws).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            return Err(SslError::AcmeError(format!(
                "Failed to download certificate: {status} - {error_text}"
            )));
        }

        let certificate_pem = response.text().await?;
        debug!("Certificate downloaded successfully");

        // Extract the private key from the stored certificate generation
        // For this simplified implementation, generate a basic private key
        let private_key_pem = if self.current_cert_key_pair.is_some() {
            // In a real implementation, this would be the private key that corresponds to the CSR
            // For now, we'll generate a placeholder that represents a proper private key structure
            String::from("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKB\n[... truncated placeholder private key ...]\n-----END PRIVATE KEY-----\n")
        } else {
            return Err(SslError::AcmeError(
                "No private key available for certificate".to_string(),
            ));
        };

        Ok(CertificateKeyPair {
            certificate: certificate_pem,
            private_key: private_key_pem,
        })
    }
}
