//! Header-based filtering for WAF

use crate::{Result, WafError};
use regex::Regex;
use std::collections::HashMap;

/// Header filter for blocking requests based on headers
pub struct HeaderFilter {
    blocked_headers: Vec<String>,
    blocked_patterns: Vec<Regex>,
}

impl HeaderFilter {
    /// Create a new header filter
    pub fn new(blocked_headers: &[String]) -> Result<Self> {
        let mut blocked_patterns = Vec::new();

        // Create regex patterns for header values
        for header in blocked_headers {
            if header.starts_with("regex:") {
                let pattern = &header[6..];
                let regex = Regex::new(pattern)
                    .map_err(|e| WafError::PatternError(format!("Invalid header regex: {}", e)))?;
                blocked_patterns.push(regex);
            }
        }

        Ok(Self {
            blocked_headers: blocked_headers.to_vec(),
            blocked_patterns,
        })
    }

    /// Check if request headers should be blocked
    pub fn check_headers(&self, headers: &HashMap<String, String>) -> bool {
        // Check for blocked header names
        for blocked_header in &self.blocked_headers {
            if !blocked_header.starts_with("regex:") && headers.contains_key(blocked_header) {
                return true; // Block request
            }
        }

        // Check header values against regex patterns
        for (_name, value) in headers {
            for pattern in &self.blocked_patterns {
                if pattern.is_match(value) {
                    return true; // Block request
                }
            }
        }

        false // Allow request
    }
}
