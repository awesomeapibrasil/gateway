use crate::{RequestContext, Result, WafError, WafResult};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// WAF rule set containing multiple rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafRuleSet {
    pub version: String,
    pub rules: Vec<WafRule>,
}

/// Individual WAF rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub enabled: bool,
    pub conditions: Vec<RuleCondition>,
    pub action: RuleAction,
    pub metadata: HashMap<String, String>,
}

/// Rule condition for matching requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    pub field: String,    // "uri", "header", "method", "query", "body", "ip"
    pub operator: String, // "equals", "contains", "regex", "starts_with", "ends_with"
    pub value: String,
    pub case_sensitive: bool,
}

/// Action to take when rule matches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleAction {
    pub action_type: String, // "block", "log", "rate_limit"
    pub message: String,
    pub score: Option<u32>,
    pub metadata: HashMap<String, String>,
}

impl WafRuleSet {
    /// Load rules from a YAML file
    pub async fn load_from_file(path: &str) -> Result<Self> {
        let content = tokio::fs::read_to_string(path).await.map_err(|e| {
            WafError::RuleParseError(format!("Failed to read file {}: {}", path, e))
        })?;

        let ruleset: WafRuleSet = serde_yaml::from_str(&content)
            .map_err(|e| WafError::RuleParseError(format!("Failed to parse YAML: {}", e)))?;

        // Validate rules
        for rule in &ruleset.rules {
            rule.validate()?;
        }

        Ok(ruleset)
    }

    /// Save rules to a YAML file
    pub async fn save_to_file(&self, path: &str) -> Result<()> {
        let content = serde_yaml::to_string(self).map_err(|e| {
            WafError::SerializationError(format!("Failed to serialize rules: {}", e))
        })?;

        tokio::fs::write(path, content)
            .await
            .map_err(|e| WafError::IoError(e))?;

        Ok(())
    }

    /// Add a new rule
    pub fn add_rule(&mut self, rule: WafRule) {
        self.rules.push(rule);
    }

    /// Remove a rule by ID
    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let initial_len = self.rules.len();
        self.rules.retain(|rule| rule.id != rule_id);
        self.rules.len() < initial_len
    }

    /// Get a rule by ID
    pub fn get_rule(&self, rule_id: &str) -> Option<&WafRule> {
        self.rules.iter().find(|rule| rule.id == rule_id)
    }

    /// Get all enabled rules
    pub fn get_enabled_rules(&self) -> Vec<&WafRule> {
        self.rules.iter().filter(|rule| rule.enabled).collect()
    }
}

impl WafRule {
    /// Evaluate the rule against a request
    pub async fn evaluate(&self, request: &RequestContext) -> Result<WafResult> {
        if !self.enabled {
            return Ok(WafResult::Allow);
        }

        // Check if all conditions match
        for condition in &self.conditions {
            if !condition.matches(request)? {
                return Ok(WafResult::Allow);
            }
        }

        // All conditions matched, execute action
        match self.action.action_type.as_str() {
            "block" => Ok(WafResult::Block(self.action.message.clone())),
            "log" => Ok(WafResult::Log(self.action.message.clone())),
            "rate_limit" => Ok(WafResult::RateLimit(self.action.message.clone())),
            _ => Ok(WafResult::Allow),
        }
    }

    /// Validate the rule configuration
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(WafError::RuleParseError(
                "Rule ID cannot be empty".to_string(),
            ));
        }

        if self.conditions.is_empty() {
            return Err(WafError::RuleParseError(format!(
                "Rule {} must have at least one condition",
                self.id
            )));
        }

        for condition in &self.conditions {
            condition.validate()?;
        }

        self.action.validate()?;

        Ok(())
    }
}

impl RuleCondition {
    /// Check if the condition matches the request
    pub fn matches(&self, request: &RequestContext) -> Result<bool> {
        let target_value = self.get_field_value(request)?;

        match self.operator.as_str() {
            "equals" => Ok(self.compare_strings(&target_value, &self.value)),
            "contains" => Ok(self.string_contains(&target_value, &self.value)),
            "starts_with" => Ok(self.string_starts_with(&target_value, &self.value)),
            "ends_with" => Ok(self.string_ends_with(&target_value, &self.value)),
            "regex" => self.regex_matches(&target_value, &self.value),
            "greater_than" => self.numeric_compare(&target_value, &self.value, |a, b| a > b),
            "less_than" => self.numeric_compare(&target_value, &self.value, |a, b| a < b),
            _ => Err(WafError::RuleParseError(format!(
                "Unknown operator: {}",
                self.operator
            ))),
        }
    }

    /// Get the field value from the request
    fn get_field_value(&self, request: &RequestContext) -> Result<String> {
        match self.field.as_str() {
            "uri" => Ok(request.uri.clone()),
            "method" => Ok(request.method.clone()),
            "ip" => Ok(request.client_ip.to_string()),
            "user_agent" => Ok(request.user_agent.clone().unwrap_or_default()),
            "content_type" => Ok(request.content_type.clone().unwrap_or_default()),
            "content_length" => Ok(request.content_length.unwrap_or(0).to_string()),
            field if field.starts_with("header.") => {
                let header_name = &field[7..]; // Remove "header." prefix
                Ok(request
                    .headers
                    .get(header_name)
                    .cloned()
                    .unwrap_or_default())
            }
            field if field.starts_with("query.") => {
                let param_name = &field[6..]; // Remove "query." prefix
                Ok(request
                    .query_params
                    .get(param_name)
                    .cloned()
                    .unwrap_or_default())
            }
            _ => Err(WafError::RuleParseError(format!(
                "Unknown field: {}",
                self.field
            ))),
        }
    }

    /// Compare strings considering case sensitivity
    fn compare_strings(&self, a: &str, b: &str) -> bool {
        if self.case_sensitive {
            a == b
        } else {
            a.to_lowercase() == b.to_lowercase()
        }
    }

    /// Check if string contains substring
    fn string_contains(&self, haystack: &str, needle: &str) -> bool {
        if self.case_sensitive {
            haystack.contains(needle)
        } else {
            haystack.to_lowercase().contains(&needle.to_lowercase())
        }
    }

    /// Check if string starts with prefix
    fn string_starts_with(&self, string: &str, prefix: &str) -> bool {
        if self.case_sensitive {
            string.starts_with(prefix)
        } else {
            string.to_lowercase().starts_with(&prefix.to_lowercase())
        }
    }

    /// Check if string ends with suffix
    fn string_ends_with(&self, string: &str, suffix: &str) -> bool {
        if self.case_sensitive {
            string.ends_with(suffix)
        } else {
            string.to_lowercase().ends_with(&suffix.to_lowercase())
        }
    }

    /// Check if string matches regex pattern
    fn regex_matches(&self, string: &str, pattern: &str) -> Result<bool> {
        let regex = Regex::new(pattern)
            .map_err(|e| WafError::PatternError(format!("Invalid regex pattern: {}", e)))?;

        Ok(regex.is_match(string))
    }

    /// Compare numeric values
    fn numeric_compare<F>(&self, a: &str, b: &str, compare_fn: F) -> Result<bool>
    where
        F: Fn(f64, f64) -> bool,
    {
        let num_a: f64 = a
            .parse()
            .map_err(|_| WafError::RuleParseError(format!("Cannot parse '{}' as number", a)))?;
        let num_b: f64 = b
            .parse()
            .map_err(|_| WafError::RuleParseError(format!("Cannot parse '{}' as number", b)))?;

        Ok(compare_fn(num_a, num_b))
    }

    /// Validate the condition
    pub fn validate(&self) -> Result<()> {
        if self.field.is_empty() {
            return Err(WafError::RuleParseError(
                "Condition field cannot be empty".to_string(),
            ));
        }

        if self.operator.is_empty() {
            return Err(WafError::RuleParseError(
                "Condition operator cannot be empty".to_string(),
            ));
        }

        // Validate regex patterns
        if self.operator == "regex" {
            Regex::new(&self.value).map_err(|e| {
                WafError::PatternError(format!("Invalid regex pattern '{}': {}", self.value, e))
            })?;
        }

        Ok(())
    }
}

impl RuleAction {
    /// Validate the action
    pub fn validate(&self) -> Result<()> {
        match self.action_type.as_str() {
            "block" | "log" | "rate_limit" => Ok(()),
            _ => Err(WafError::RuleParseError(format!(
                "Invalid action type: {}",
                self.action_type
            ))),
        }
    }
}

impl Default for WafRuleSet {
    fn default() -> Self {
        Self {
            version: "1.0".to_string(),
            rules: vec![
                // Basic SQL injection protection
                WafRule {
                    id: "sql_injection_basic".to_string(),
                    name: "Basic SQL Injection Protection".to_string(),
                    description: "Detects common SQL injection patterns".to_string(),
                    severity: "high".to_string(),
                    enabled: true,
                    conditions: vec![RuleCondition {
                        field: "uri".to_string(),
                        operator: "regex".to_string(),
                        value: r"(?i)(union\s+select|drop\s+table|delete\s+from|insert\s+into)"
                            .to_string(),
                        case_sensitive: false,
                    }],
                    action: RuleAction {
                        action_type: "block".to_string(),
                        message: "SQL injection attempt detected".to_string(),
                        score: Some(100),
                        metadata: HashMap::new(),
                    },
                    metadata: HashMap::new(),
                },
                // Basic XSS protection
                WafRule {
                    id: "xss_basic".to_string(),
                    name: "Basic XSS Protection".to_string(),
                    description: "Detects common XSS patterns".to_string(),
                    severity: "high".to_string(),
                    enabled: true,
                    conditions: vec![RuleCondition {
                        field: "uri".to_string(),
                        operator: "regex".to_string(),
                        value: r"(?i)(<script|</script>|javascript:|vbscript:)".to_string(),
                        case_sensitive: false,
                    }],
                    action: RuleAction {
                        action_type: "block".to_string(),
                        message: "XSS attempt detected".to_string(),
                        score: Some(100),
                        metadata: HashMap::new(),
                    },
                    metadata: HashMap::new(),
                },
                // Directory traversal protection
                WafRule {
                    id: "directory_traversal".to_string(),
                    name: "Directory Traversal Protection".to_string(),
                    description: "Detects directory traversal attempts".to_string(),
                    severity: "medium".to_string(),
                    enabled: true,
                    conditions: vec![RuleCondition {
                        field: "uri".to_string(),
                        operator: "contains".to_string(),
                        value: "../".to_string(),
                        case_sensitive: true,
                    }],
                    action: RuleAction {
                        action_type: "block".to_string(),
                        message: "Directory traversal attempt detected".to_string(),
                        score: Some(75),
                        metadata: HashMap::new(),
                    },
                    metadata: HashMap::new(),
                },
            ],
        }
    }
}
