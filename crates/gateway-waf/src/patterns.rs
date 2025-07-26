//! Pattern matching utilities for WAF

use regex::Regex;
use std::collections::HashMap;

/// Pattern matcher for various WAF rules
pub struct PatternMatcher {
    patterns: HashMap<String, Regex>,
}

impl PatternMatcher {
    /// Create a new pattern matcher
    pub fn new() -> Self {
        Self {
            patterns: HashMap::new(),
        }
    }

    /// Add a pattern
    pub fn add_pattern(&mut self, name: String, pattern: &str) -> Result<(), regex::Error> {
        let regex = Regex::new(pattern)?;
        self.patterns.insert(name, regex);
        Ok(())
    }

    /// Check if text matches any pattern
    pub fn matches(&self, text: &str) -> Vec<String> {
        self.patterns
            .iter()
            .filter_map(|(name, regex)| {
                if regex.is_match(text) {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Check if text matches a specific pattern
    pub fn matches_pattern(&self, pattern_name: &str, text: &str) -> bool {
        self.patterns
            .get(pattern_name)
            .map(|regex| regex.is_match(text))
            .unwrap_or(false)
    }
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}
