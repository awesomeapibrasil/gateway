use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Simplified Kubernetes Ingress resource representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressResource {
    pub metadata: IngressMetadata,
    pub spec: IngressSpec,
    pub status: Option<IngressStatus>,
}

/// Ingress metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressMetadata {
    pub name: String,
    pub namespace: String,
    pub annotations: HashMap<String, String>,
    pub labels: HashMap<String, String>,
    pub uid: String,
    pub resource_version: String,
    pub creation_timestamp: String,
}

/// Ingress specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressSpec {
    pub ingress_class_name: Option<String>,
    pub default_backend: Option<IngressBackend>,
    pub tls: Vec<IngressTls>,
    pub rules: Vec<IngressRule>,
}

/// Ingress TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressTls {
    pub hosts: Vec<String>,
    pub secret_name: Option<String>,
}

/// Ingress rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRule {
    pub host: Option<String>,
    pub http: Option<IngressHttp>,
}

/// HTTP rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressHttp {
    pub paths: Vec<IngressPath>,
}

/// Ingress path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressPath {
    pub path: Option<String>,
    pub path_type: String, // "Exact", "Prefix", "ImplementationSpecific"
    pub backend: IngressBackend,
}

/// Ingress backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressBackend {
    pub service: Option<IngressServiceBackend>,
    pub resource: Option<IngressResourceBackend>,
}

/// Service backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressServiceBackend {
    pub name: String,
    pub port: IngressServicePort,
}

/// Service port
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressServicePort {
    pub name: Option<String>,
    pub number: Option<u16>,
}

/// Resource backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressResourceBackend {
    pub api_version: String,
    pub kind: String,
    pub name: String,
}

/// Ingress status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressStatus {
    pub load_balancer: Option<IngressLoadBalancerStatus>,
}

/// Load balancer status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressLoadBalancerStatus {
    pub ingress: Vec<IngressLoadBalancerIngress>,
}

/// Load balancer ingress
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressLoadBalancerIngress {
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub ports: Vec<IngressPortStatus>,
}

/// Port status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressPortStatus {
    pub port: u16,
    pub protocol: String,
    pub error: Option<String>,
}

impl IngressResource {
    /// Check if this ingress should be handled by our controller
    pub fn should_handle(&self, ingress_class: &str) -> bool {
        if let Some(class_name) = &self.spec.ingress_class_name {
            class_name == ingress_class
        } else {
            // Check for deprecated annotation
            self.metadata
                .annotations
                .get("kubernetes.io/ingress.class")
                .map(|v| v == ingress_class)
                .unwrap_or(false)
        }
    }

    /// Get all hosts from the ingress
    pub fn get_hosts(&self) -> Vec<String> {
        let mut hosts = Vec::new();

        // Collect hosts from rules
        for rule in &self.spec.rules {
            if let Some(host) = &rule.host {
                hosts.push(host.clone());
            }
        }

        // Collect hosts from TLS configuration
        for tls in &self.spec.tls {
            hosts.extend(tls.hosts.clone());
        }

        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// Get TLS hosts that need certificates
    pub fn get_tls_hosts(&self) -> Vec<String> {
        let mut hosts = Vec::new();

        for tls in &self.spec.tls {
            hosts.extend(tls.hosts.clone());
        }

        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// Check if the ingress has TLS configuration
    pub fn has_tls(&self) -> bool {
        !self.spec.tls.is_empty()
    }

    /// Get unique identifier for the ingress
    pub fn get_id(&self) -> String {
        format!("{}/{}", self.metadata.namespace, self.metadata.name)
    }
}

impl IngressPath {
    /// Check if a request path matches this ingress path
    pub fn matches(&self, request_path: &str) -> bool {
        match self.path_type.as_str() {
            "Exact" => {
                if let Some(path) = &self.path {
                    request_path == path
                } else {
                    false
                }
            }
            "Prefix" => {
                if let Some(path) = &self.path {
                    request_path.starts_with(path)
                } else {
                    true // No path means match all
                }
            }
            "ImplementationSpecific" => {
                // For our implementation, treat as prefix
                if let Some(path) = &self.path {
                    request_path.starts_with(path)
                } else {
                    true
                }
            }
            _ => false,
        }
    }
}

impl IngressBackend {
    /// Get the backend service name and port
    pub fn get_service_info(&self) -> Option<(String, Option<u16>)> {
        self.service
            .as_ref()
            .map(|svc| (svc.name.clone(), svc.port.number))
    }
}
