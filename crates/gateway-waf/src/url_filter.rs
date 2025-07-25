//! URL-based filtering for WAF

use regex::Regex;
use crate::{WafError, Result};

/// URL filter for blocking requests based on URL patterns
pub struct UrlFilter {
    blocked_patterns: Vec<Regex>,
    blocked_extensions: Vec<String>,
}

impl UrlFilter {
    /// Create a new URL filter
    pub fn new() -> Self {
        Self {
            blocked_patterns: Self::default_patterns(),
            blocked_extensions: Self::default_extensions(),
        }
    }

    /// Check if URL should be blocked
    pub fn check_url(&self, url: &str) -> bool {
        // Check against patterns
        for pattern in &self.blocked_patterns {
            if pattern.is_match(url) {
                return true; // Block request
            }
        }

        // Check file extensions
        for ext in &self.blocked_extensions {
            if url.ends_with(ext) {
                return true; // Block request
            }
        }

        false // Allow request
    }

    /// Default malicious patterns
    fn default_patterns() -> Vec<Regex> {
        let patterns = [
            r"\.\.[\\/]",           // Directory traversal
            r"<script[^>]*>",       // XSS
            r"javascript:",         // JavaScript protocol
            r"vbscript:",          // VBScript protocol
            r"union\s+select",     // SQL injection
            r"drop\s+table",       // SQL injection
            r"exec\(",            // Code execution
            r"eval\(",            // Code execution
        ];

        patterns.iter()
            .filter_map(|&p| Regex::new(&format!("(?i){}", p)).ok())
            .collect()
    }

    /// Default blocked extensions
    fn default_extensions() -> Vec<String> {
        vec![
            ".exe".to_string(),
            ".bat".to_string(),
            ".cmd".to_string(),
            ".com".to_string(),
            ".scr".to_string(),
            ".pif".to_string(),
        ]
    }
}