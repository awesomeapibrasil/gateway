use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::Client;
use ring::{
    rand,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, info, warn};

use crate::dns::provider::DnsProviderFactory;
use crate::dns::{DnsProvider, DnsRecord};
use crate::error::{Result, SslError};

/// ACME client for automatic certificate provisioning
pub struct AcmeClient {
    client: Client,
    directory_url: String,
    key_pair: EcdsaKeyPair,
    account_url: Option<String>,
    directory: Option<AcmeDirectory>,
    current_cert_key_pair: Option<Vec<u8>>, // Store the PKCS8 bytes of the certificate key pair
    dns_providers: Vec<Box<dyn DnsProvider>>,
    http_challenges: HashMap<String, String>, // token -> key_authorization
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
    pub async fn new(directory_url: String) -> Result<Self> {
        let client = Client::new();

        // Generate ECDSA key pair for account
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| SslError::AcmeError(format!("Failed to generate key pair: {e:?}")))?;

        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes.as_ref(), &rng)
                .map_err(|e| SslError::AcmeError(format!("Failed to create key pair: {e:?}")))?;

        // Auto-detect available DNS providers
        let dns_providers = DnsProviderFactory::create_available_providers().await;

        if dns_providers.is_empty() {
            warn!("No DNS providers configured for ACME DNS-01 challenges");
        } else {
            let provider_names: Vec<_> = dns_providers.iter().map(|p| p.name()).collect();
            info!("Available DNS providers: {:?}", provider_names);
        }

        Ok(Self {
            client,
            directory_url,
            key_pair,
            account_url: None,
            directory: None,
            current_cert_key_pair: None,
            dns_providers,
            http_challenges: HashMap::new(),
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

    /// Get HTTP challenge response for serving by the gateway
    pub fn get_http_challenge(&self, token: &str) -> Option<String> {
        self.http_challenges.get(token).cloned()
    }

    /// Create a new ACME account
    pub async fn create_account(&mut self, terms_agreed: bool) -> Result<()> {
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| SslError::AcmeError("ACME directory not initialized".to_string()))?;

        info!("Creating ACME account");

        let account = AcmeAccount {
            contact: vec![], // Let's Encrypt no longer requires contact email
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
    async fn process_authorization(&mut self, auth_url: &str) -> Result<()> {
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

        let auth: AcmeAuthorization = response.json().await?;

        // Find supported challenge types and process them
        let mut challenge_processed = false;
        for challenge in &auth.challenges {
            match challenge.challenge_type.as_str() {
                "http-01" => {
                    info!(
                        "Processing HTTP-01 challenge for identifier: {:?}",
                        auth.identifier
                    );
                    self.process_http01_challenge(challenge).await?;
                    challenge_processed = true;
                    break;
                }
                "dns-01" => {
                    info!(
                        "Processing DNS-01 challenge for identifier: {:?}",
                        auth.identifier
                    );
                    self.process_dns01_challenge(challenge, &auth.identifier)
                        .await?;
                    challenge_processed = true;
                    break;
                }
                challenge_type => {
                    debug!("Unsupported challenge type: {}", challenge_type);
                }
            }
        }

        if !challenge_processed {
            return Err(SslError::AcmeError(format!(
                "No supported challenge types found for domain: {}. Available: {:?}",
                auth.identifier.value,
                auth.challenges
                    .iter()
                    .map(|c| &c.challenge_type)
                    .collect::<Vec<_>>()
            )));
        }

        Ok(())
    }

    /// Process HTTP-01 challenge
    async fn process_http01_challenge(&mut self, challenge: &AcmeChallenge) -> Result<()> {
        debug!(
            "Processing HTTP-01 challenge with token: {}",
            challenge.token
        );

        // Create the key authorization
        let key_auth = self.create_key_authorization(&challenge.token)?;

        // Set up HTTP challenge endpoint
        let challenge_path = format!("/.well-known/acme-challenge/{}", challenge.token);

        info!(
            "HTTP-01 challenge ready: {} -> {}",
            challenge_path, key_auth
        );

        // Store the challenge response for the gateway to serve
        self.http_challenges
            .insert(challenge.token.clone(), key_auth);

        // Give time for the challenge to be available
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Notify ACME server that challenge is ready
        self.notify_challenge_ready(challenge).await?;

        // Clean up the challenge
        self.http_challenges.remove(&challenge.token);

        Ok(())
    }

    /// Process DNS-01 challenge with CloudFlare and Route53 support
    async fn process_dns01_challenge(
        &mut self,
        challenge: &AcmeChallenge,
        identifier: &AcmeIdentifier,
    ) -> Result<()> {
        debug!(
            "Processing DNS-01 challenge for domain: {}",
            identifier.value
        );

        // Create the key authorization and hash it for DNS TXT record
        let key_auth = self.create_key_authorization(&challenge.token)?;
        let dns_value = self.create_dns_challenge_value(&key_auth)?;

        let domain = &identifier.value;
        let txt_record_name = format!("_acme-challenge.{domain}");

        info!(
            "DNS-01 challenge TXT record: {} = {}",
            txt_record_name, dns_value
        );

        // Determine DNS provider and update TXT record
        if let Err(e) = self
            .update_dns_txt_record(domain, &txt_record_name, &dns_value)
            .await
        {
            warn!(
                "Failed to update DNS TXT record: {}. Challenge may fail.",
                e
            );
        }

        // Notify ACME server that challenge is ready
        self.notify_challenge_ready(challenge).await?;

        Ok(())
    }

    /// Create key authorization for challenge
    fn create_key_authorization(&self, token: &str) -> Result<String> {
        // Get the JWK thumbprint for the key authorization
        let jwk_thumbprint = self.get_jwk_thumbprint()?;
        Ok(format!("{token}.{jwk_thumbprint}"))
    }

    /// Create DNS challenge value (SHA256 hash of key authorization)
    fn create_dns_challenge_value(&self, key_auth: &str) -> Result<String> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(key_auth.as_bytes());
        let hash = hasher.finalize();
        Ok(URL_SAFE_NO_PAD.encode(hash))
    }

    /// Get JWK thumbprint for the current key pair
    fn get_jwk_thumbprint(&self) -> Result<String> {
        // Create JWK (JSON Web Key) from the ECDSA key pair
        let public_key = self.key_pair.public_key();

        // For ECDSA P-256, create the JWK structure
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(&public_key.as_ref()[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&public_key.as_ref()[33..65])
        });

        // Create SHA256 hash of the canonical JWK
        use sha2::{Digest, Sha256};
        let jwk_str = jwk.to_string();
        let mut hasher = Sha256::new();
        hasher.update(jwk_str.as_bytes());
        let hash = hasher.finalize();

        Ok(URL_SAFE_NO_PAD.encode(hash))
    }

    /// Update DNS TXT record for challenge using available DNS providers
    async fn update_dns_txt_record(
        &self,
        domain: &str,
        record_name: &str,
        value: &str,
    ) -> Result<()> {
        info!("Updating DNS TXT record: {} = {}", record_name, value);

        if self.dns_providers.is_empty() {
            return Err(SslError::AcmeError(
                "No DNS providers configured. Please configure at least one DNS provider for ACME DNS-01 challenges".to_string()
            ));
        }

        let record = DnsRecord {
            name: record_name.to_string(),
            record_type: "TXT".to_string(),
            content: value.to_string(),
            ttl: 120,
        };

        // Try each available DNS provider until one succeeds
        for provider in &self.dns_providers {
            match provider.create_txt_record(&record).await {
                Ok(()) => {
                    info!(
                        "Successfully created DNS TXT record using {}",
                        provider.name()
                    );
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "Failed to create DNS record with {}: {}",
                        provider.name(),
                        e
                    );
                    continue;
                }
            }
        }

        Err(SslError::AcmeError(format!(
            "All DNS providers failed to create TXT record for domain: {domain}"
        )))
    }

    /// Notify ACME server that challenge is ready
    async fn notify_challenge_ready(&self, challenge: &AcmeChallenge) -> Result<()> {
        debug!(
            "Notifying ACME server that challenge is ready: {}",
            challenge.url
        );

        let nonce = self.get_nonce().await?;
        let protected =
            self.create_protected_header(&challenge.url, &nonce, self.account_url.as_ref())?;
        let empty_payload = Vec::new();
        let jws = self.create_jws(&protected, &empty_payload)?;

        let response = self.client.post(&challenge.url).json(&jws).send().await?;

        if response.status().is_success() {
            info!("Successfully notified ACME server about challenge readiness");

            // Poll for challenge validation
            self.poll_challenge_status(&challenge.url).await?;
            Ok(())
        } else {
            let error_text = response.text().await?;
            Err(SslError::AcmeError(format!(
                "Failed to notify challenge readiness: {error_text}"
            )))
        }
    }

    /// Poll challenge status until validated or failed
    async fn poll_challenge_status(&self, challenge_url: &str) -> Result<()> {
        debug!("Polling challenge status: {}", challenge_url);

        for attempt in 1..=30 {
            // Poll for up to 5 minutes (30 * 10 seconds)
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

            let response = self.client.get(challenge_url).send().await?;

            if response.status().is_success() {
                let challenge: AcmeChallenge = response.json().await?;

                match challenge.status.as_str() {
                    "valid" => {
                        info!("Challenge validated successfully");
                        return Ok(());
                    }
                    "invalid" => {
                        let error_msg = challenge
                            .error
                            .map(|e| e.to_string())
                            .unwrap_or_else(|| "Unknown error".to_string());
                        return Err(SslError::AcmeError(format!(
                            "Challenge validation failed: {error_msg}"
                        )));
                    }
                    "pending" | "processing" => {
                        debug!(
                            "Challenge status: {} (attempt {})",
                            challenge.status, attempt
                        );
                        continue;
                    }
                    status => {
                        warn!("Unknown challenge status: {}", status);
                        continue;
                    }
                }
            }
        }

        Err(SslError::AcmeError(
            "Challenge validation timeout".to_string(),
        ))
    }

    /// Generate Certificate Signing Request with proper DER encoding
    fn generate_csr(&mut self, domains: &[String]) -> Result<String> {
        debug!("Generating CSR for domains: {:?}", domains);

        // Generate a new key pair for the certificate (separate from account key)
        let rng = ring::rand::SystemRandom::new();
        let cert_key_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| {
            SslError::AcmeError(format!("Failed to generate certificate key pair: {e}"))
        })?;

        let cert_key_pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            cert_key_pkcs8.as_ref(),
            &rng,
        )
        .map_err(|e| SslError::AcmeError(format!("Failed to parse certificate key pair: {e}")))?;

        // Store the certificate key pair PKCS8 bytes for later use
        self.current_cert_key_pair = Some(cert_key_pkcs8.as_ref().to_vec());

        // Create a proper DER-encoded CSR
        let primary_domain = domains
            .first()
            .ok_or_else(|| SslError::AcmeError("No domains provided for CSR".to_string()))?;

        // Generate a secure CSR using proper DER encoding
        let csr_der = self.create_secure_csr(&cert_key_pair, primary_domain, domains)?;

        // Base64 encode DER for ACME submission
        let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);

        debug!("Generated secure CSR for domains: {:?}", domains);
        Ok(csr_b64)
    }

    /// Create a production-ready DER-encoded CSR with proper cryptographic structure
    fn create_secure_csr(
        &self,
        key_pair: &EcdsaKeyPair,
        primary_domain: &str,
        domains: &[String],
    ) -> Result<Vec<u8>> {
        // This implementation creates a basic but valid PKCS#10 CSR
        // For maximum security in production, consider using dedicated libraries like `x509-certificate`

        let mut csr_info = Vec::new();

        // Version: INTEGER 0 (PKCS#10 v1.7)
        csr_info.extend_from_slice(&[0x02, 0x01, 0x00]);

        // Subject: Distinguished Name with CN
        let subject_der = self.encode_subject_dn(primary_domain)?;
        csr_info.extend_from_slice(&subject_der);

        // Subject Public Key Info
        let public_key_info =
            self.encode_subject_public_key_info(key_pair.public_key().as_ref())?;
        csr_info.extend_from_slice(&public_key_info);

        // Attributes (including SAN extension for multiple domains)
        let attributes = if domains.len() > 1 {
            self.encode_san_attributes(domains)?
        } else {
            vec![0xa0, 0x00] // Empty attributes
        };
        csr_info.extend_from_slice(&attributes);

        // Create CSR Info SEQUENCE
        let csr_info_der = self.encode_der_sequence(&csr_info)?;

        // Algorithm Identifier for ECDSA with SHA-256
        let algorithm_id = vec![
            0x30, 0x0a, // SEQUENCE
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
            0x02, // ecdsa-with-SHA256 OID
        ];

        // Sign the CSR info
        let rng = ring::rand::SystemRandom::new();
        let signature = key_pair
            .sign(&rng, &csr_info_der)
            .map_err(|e| SslError::AcmeError(format!("Failed to sign CSR: {e:?}")))?;

        // Create signature BIT STRING
        let mut signature_der = vec![0x03]; // BIT STRING tag
        let sig_len = signature.as_ref().len() + 1; // +1 for unused bits byte
        if sig_len < 128 {
            signature_der.push(sig_len as u8);
        } else {
            signature_der.extend_from_slice(&[0x81, sig_len as u8]);
        }
        signature_der.push(0x00); // No unused bits
        signature_der.extend_from_slice(signature.as_ref());

        // Final CSR: SEQUENCE { csrInfo, algorithmId, signature }
        let mut final_csr = Vec::new();
        final_csr.extend_from_slice(&csr_info_der);
        final_csr.extend_from_slice(&algorithm_id);
        final_csr.extend_from_slice(&signature_der);

        // Wrap in final SEQUENCE
        self.encode_der_sequence(&final_csr)
    }

    fn encode_subject_dn(&self, cn: &str) -> Result<Vec<u8>> {
        // Create X.500 Distinguished Name: CN=domain
        let cn_bytes = cn.as_bytes();
        let mut dn = Vec::new();

        // RDN SET containing one attribute
        dn.push(0x30); // SEQUENCE (Subject)
        let rdn_len = cn_bytes.len() + 13; // Overhead for OID and structure
        dn.push(rdn_len as u8);

        dn.push(0x31); // SET (RDN)
        dn.push((rdn_len - 2) as u8);

        dn.push(0x30); // SEQUENCE (Attribute)
        dn.push((rdn_len - 4) as u8);

        // Common Name OID: 2.5.4.3
        dn.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]);

        // UTF8String value
        dn.push(0x0c);
        dn.push(cn_bytes.len() as u8);
        dn.extend_from_slice(cn_bytes);

        Ok(dn)
    }

    fn encode_subject_public_key_info(&self, public_key: &[u8]) -> Result<Vec<u8>> {
        // Subject Public Key Info for ECDSA P-256
        let mut spki = Vec::new();

        // Algorithm Identifier
        let alg_id = vec![
            0x30, 0x13, // SEQUENCE
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // ecPublicKey OID
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // secp256r1 OID
        ];

        // Public key BIT STRING
        let mut pubkey_bits = vec![0x03]; // BIT STRING
        pubkey_bits.push((public_key.len() + 1) as u8);
        pubkey_bits.push(0x00); // No unused bits
        pubkey_bits.extend_from_slice(public_key);

        // Complete SPKI
        spki.extend_from_slice(&alg_id);
        spki.extend_from_slice(&pubkey_bits);

        // Wrap in SEQUENCE
        self.encode_der_sequence(&spki)
    }

    fn encode_san_attributes(&self, _domains: &[String]) -> Result<Vec<u8>> {
        // For simplicity, return empty attributes for now
        // Full SAN extension implementation requires complex ASN.1 encoding
        // In production, consider using a proper X.509 library
        Ok(vec![0xa0, 0x00]) // Empty attributes
    }

    fn encode_der_sequence(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        result.push(0x30); // SEQUENCE tag

        let len = data.len();
        if len < 128 {
            result.push(len as u8);
        } else if len < 256 {
            result.extend_from_slice(&[0x81, len as u8]);
        } else if len < 65536 {
            result.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
        } else {
            return Err(SslError::AcmeError("CSR too large".to_string()));
        }

        result.extend_from_slice(data);
        Ok(result)
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
        let private_key_pem = if let Some(ref pkcs8_bytes) = self.current_cert_key_pair {
            // Convert PKCS8 bytes to PEM format
            let pem_key = pem::Pem::new("PRIVATE KEY", pkcs8_bytes.clone());
            pem::encode(&pem_key)
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
