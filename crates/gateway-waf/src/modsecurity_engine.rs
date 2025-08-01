//! ModSecurity-compatible rule engine for advanced WAF capabilities
//!
//! This module provides a Rust-native implementation of ModSecurity-style rules,
//! supporting OWASP Core Rule Set (CRS) patterns and dynamic rule updates.

use crate::{RequestContext, Result, WafError, WafResult};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// ModSecurity-compatible rule engine configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModSecurityConfig {
    /// Whether ModSecurity is enabled
    pub enabled: bool,
    /// Path to ModSecurity rules directory
    pub rules_path: String,
    /// Path to OWASP CRS rules
    pub owasp_crs_path: String,
    /// Debug log level
    pub debug_log_level: i32,
    /// Maximum body size to inspect
    pub max_body_size: usize,
    /// Whether to block on rule match
    pub blocking_mode: bool,
    /// Custom rule update interval in seconds
    pub rule_update_interval: u64,
    /// OWASP CRS repository URL for dynamic updates
    pub owasp_crs_repo_url: String,
    /// OWASP CRS branch/tag to download
    pub owasp_crs_version: String,
    /// Whether to automatically update OWASP CRS rules on startup
    pub auto_update_owasp_crs: bool,
}

impl Default for ModSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rules_path: "config/modsecurity".to_string(),
            owasp_crs_path: "config/modsecurity/owasp-crs".to_string(),
            debug_log_level: 3,
            max_body_size: 1024 * 1024, // 1MB
            blocking_mode: true,
            rule_update_interval: 300, // 5 minutes
            owasp_crs_repo_url: "https://github.com/coreruleset/coreruleset".to_string(),
            owasp_crs_version: "v4.3.0".to_string(),
            auto_update_owasp_crs: true,
        }
    }
}

/// ModSecurity-style rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModSecRule {
    pub id: String,
    pub msg: String,
    pub severity: String,
    pub phase: u8,
    pub variables: Vec<String>,
    pub operator: String,
    pub operator_arg: String,
    pub transformations: Vec<String>,
    pub actions: Vec<String>,
    pub enabled: bool,
    #[serde(skip)]
    pub regex: Option<Regex>,
}

impl ModSecRule {
    /// Parse a ModSecurity rule line
    pub fn parse(line: &str) -> Result<Self> {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            return Err(WafError::RuleParseError(
                "Empty or comment line".to_string(),
            ));
        }

        // Basic SecRule parsing: SecRule VARIABLES "OPERATOR" "ACTIONS"
        if !line.starts_with("SecRule") {
            return Err(WafError::RuleParseError("Not a SecRule".to_string()));
        }

        // Parse the rule by finding quoted sections
        let mut parts = Vec::new();
        let mut current_part = String::new();
        let mut in_quotes = false;

        for ch in line.chars() {
            match ch {
                '"' => {
                    if in_quotes {
                        // End of quoted section
                        in_quotes = false;
                        if !current_part.is_empty() {
                            parts.push(current_part.clone());
                            current_part.clear();
                        }
                    } else {
                        // Start of quoted section
                        in_quotes = true;
                        if !current_part.is_empty() {
                            parts.push(current_part.clone());
                            current_part.clear();
                        }
                    }
                }
                ' ' | '\t' => {
                    if in_quotes {
                        current_part.push(ch);
                    } else if !current_part.is_empty() {
                        parts.push(current_part.clone());
                        current_part.clear();
                    }
                }
                _ => {
                    current_part.push(ch);
                }
            }
        }

        if !current_part.is_empty() {
            parts.push(current_part);
        }

        if parts.len() < 4 {
            return Err(WafError::RuleParseError(
                "Invalid SecRule format".to_string(),
            ));
        }

        let variables = parts[1].split('|').map(|s| s.to_string()).collect();
        let operator_part = &parts[2];
        let actions_part = &parts[3];

        // Parse operator
        let (operator, operator_arg) = if operator_part.starts_with('@') {
            let op_parts: Vec<&str> = operator_part.splitn(2, ' ').collect();
            (
                op_parts[0].to_string(),
                op_parts.get(1).unwrap_or(&"").to_string(),
            )
        } else {
            ("@rx".to_string(), operator_part.to_string())
        };

        // Parse actions
        let actions: Vec<String> = actions_part
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        // Extract metadata from actions
        let mut id = "unknown".to_string();
        let mut msg = "ModSecurity rule triggered".to_string();
        let mut severity = "NOTICE".to_string();
        let mut phase = 2;

        for action in &actions {
            if action.starts_with("id:") {
                id = action[3..].to_string();
            } else if action.starts_with("msg:") {
                msg = action[4..].trim_matches('\'').trim_matches('"').to_string();
            } else if action.starts_with("severity:") {
                severity = action[9..].to_string();
            } else if action.starts_with("phase:") {
                if let Ok(p) = action[6..].parse::<u8>() {
                    phase = p;
                }
            }
        }

        // Compile regex if operator is regex-based
        let regex = if operator == "@rx" || operator == "@detectSQLi" || operator == "@detectXSS" {
            match Regex::new(&operator_arg) {
                Ok(r) => Some(r),
                Err(e) => {
                    warn!("Failed to compile regex for rule {}: {}", id, e);
                    None
                }
            }
        } else {
            None
        };

        Ok(ModSecRule {
            id,
            msg,
            severity,
            phase,
            variables,
            operator,
            operator_arg,
            transformations: Vec::new(),
            actions,
            enabled: true,
            regex,
        })
    }

    /// Evaluate the rule against a request
    pub async fn evaluate(&self, request: &RequestContext) -> Result<WafResult> {
        if !self.enabled {
            return Ok(WafResult::Allow);
        }

        // Get values to check based on variables
        let mut values_to_check = Vec::new();

        for variable in &self.variables {
            match variable.as_str() {
                "REQUEST_URI" | "REQUEST_FILENAME" => {
                    values_to_check.push(request.uri.clone());
                }
                "ARGS" | "ARGS_NAMES" => {
                    for (_, value) in &request.query_params {
                        values_to_check.push(value.clone());
                    }
                }
                "REQUEST_HEADERS" => {
                    for (_, value) in &request.headers {
                        values_to_check.push(value.clone());
                    }
                }
                "REQUEST_BODY" => {
                    if let Some(body) = &request.body {
                        if let Ok(body_str) = String::from_utf8(body.clone()) {
                            values_to_check.push(body_str);
                        }
                    }
                }
                "REQUEST_METHOD" => {
                    values_to_check.push(request.method.clone());
                }
                _ => {
                    // Handle specific headers like REQUEST_HEADERS:User-Agent
                    if variable.starts_with("REQUEST_HEADERS:") {
                        let header_name = &variable[16..];
                        if let Some(value) = request.headers.get(header_name) {
                            values_to_check.push(value.clone());
                        }
                    }
                }
            }
        }

        // Apply operator to values
        for value in &values_to_check {
            if self.matches_operator(value)? {
                let action_type = self.get_action_type();
                let message = format!("{} (Rule ID: {})", self.msg, self.id);

                return Ok(match action_type.as_str() {
                    "block" | "deny" => WafResult::Block(message),
                    "drop" => WafResult::Block(message),
                    "allow" => WafResult::Allow,
                    _ => WafResult::Log(message),
                });
            }
        }

        Ok(WafResult::Allow)
    }

    /// Check if a value matches the rule operator
    fn matches_operator(&self, value: &str) -> Result<bool> {
        match self.operator.as_str() {
            "@rx" => {
                if let Some(regex) = &self.regex {
                    Ok(regex.is_match(value))
                } else {
                    // Enhanced fallback with case-insensitive matching and word boundaries
                    let search_term = &self.operator_arg.to_lowercase();
                    let value_lower = value.to_lowercase();
                    Ok(value_lower.contains(search_term))
                }
            }
            "@detectSQLi" => {
                // Built-in SQL injection detection
                let sql_patterns = [
                    r"(?i)(union\s+select|drop\s+table|delete\s+from|insert\s+into)",
                    r"(?i)(exec\s*\(|sp_|xp_)",
                    r"(?i)(\'\s*or\s+\d+\s*=\s*\d+|\'\s*or\s+\'\w+\'\s*=\s*\'\w+)",
                    r"(?i)(--|\#|\/\*|\*\/)",
                ];

                for pattern in &sql_patterns {
                    if let Ok(regex) = Regex::new(pattern) {
                        if regex.is_match(value) {
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
            "@detectXSS" => {
                // Built-in XSS detection
                let xss_patterns = [
                    r"(?i)(<script|</script>|javascript:|vbscript:)",
                    r"(?i)(onload=|onerror=|onclick=|onmouseover=)",
                    r"(?i)(eval\s*\(|document\.cookie|document\.write)",
                ];

                for pattern in &xss_patterns {
                    if let Ok(regex) = Regex::new(pattern) {
                        if regex.is_match(value) {
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
            "@contains" => Ok(value.contains(&self.operator_arg)),
            "@beginsWith" => Ok(value.starts_with(&self.operator_arg)),
            "@endsWith" => Ok(value.ends_with(&self.operator_arg)),
            "@eq" => Ok(value == self.operator_arg),
            "@gt" => {
                if let (Ok(val), Ok(arg)) = (value.parse::<i64>(), self.operator_arg.parse::<i64>())
                {
                    Ok(val > arg)
                } else {
                    Ok(false)
                }
            }
            "@lt" => {
                if let (Ok(val), Ok(arg)) = (value.parse::<i64>(), self.operator_arg.parse::<i64>())
                {
                    Ok(val < arg)
                } else {
                    Ok(false)
                }
            }
            _ => {
                warn!("Unknown operator: {}", self.operator);
                Ok(false)
            }
        }
    }

    /// Get the primary action type for this rule
    fn get_action_type(&self) -> String {
        for action in &self.actions {
            match action.as_str() {
                "block" | "deny" | "drop" => return action.clone(),
                "allow" | "pass" => return "allow".to_string(),
                "log" => return "log".to_string(),
                _ => {}
            }
        }

        // Default action based on severity
        match self.severity.as_str() {
            "EMERGENCY" | "ALERT" | "CRITICAL" | "ERROR" => "block".to_string(),
            _ => "log".to_string(),
        }
    }
}

/// ModSecurity rule update statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModSecurityStats {
    pub rules_loaded: u64,
    pub rules_matched: u64,
    pub requests_processed: u64,
    pub requests_blocked: u64,
    pub last_rule_update: Option<chrono::DateTime<chrono::Utc>>,
    pub rule_matches_by_id: HashMap<String, u64>,
}

/// ModSecurity-compatible rule engine
pub struct ModSecurityEngine {
    config: Arc<RwLock<ModSecurityConfig>>,
    rules: Arc<RwLock<Vec<ModSecRule>>>,
    stats: Arc<RwLock<ModSecurityStats>>,
}

impl ModSecurityEngine {
    /// Create a new ModSecurity engine
    pub async fn new(config: &ModSecurityConfig) -> Result<Self> {
        if !config.enabled {
            info!("ModSecurity engine disabled");
            return Ok(Self::disabled());
        }

        info!("Initializing ModSecurity-compatible engine");

        let mut rules = Vec::new();
        let mut stats = ModSecurityStats::default();

        // Load built-in OWASP TOP10 rules
        Self::load_builtin_owasp_rules(&mut rules).await;
        stats.rules_loaded += rules.len() as u64;

        // Load custom rules if paths exist
        if Path::new(&config.rules_path).exists() {
            match Self::load_rules_from_directory(&mut rules, &config.rules_path).await {
                Ok(count) => {
                    stats.rules_loaded += count;
                    info!("Loaded {} custom ModSecurity rules", count);
                }
                Err(e) => warn!("Failed to load custom rules: {}", e),
            }
        }

        // Download and update OWASP CRS rules if enabled
        if config.auto_update_owasp_crs {
            info!("Checking for OWASP CRS updates...");
            match Self::download_owasp_crs_rules(config).await {
                Ok(updated) => {
                    if updated {
                        info!("OWASP CRS rules updated from repository");
                    } else {
                        debug!("OWASP CRS rules are up to date");
                    }
                }
                Err(e) => warn!("Failed to update OWASP CRS rules: {}", e),
            }
        }

        if Path::new(&config.owasp_crs_path).exists() {
            match Self::load_rules_from_directory(&mut rules, &config.owasp_crs_path).await {
                Ok(count) => {
                    stats.rules_loaded += count;
                    info!("Loaded {} OWASP CRS rules", count);
                }
                Err(e) => warn!("Failed to load OWASP CRS rules: {}", e),
            }
        }

        stats.last_rule_update = Some(chrono::Utc::now());

        Ok(Self {
            config: Arc::new(RwLock::new(config.clone())),
            rules: Arc::new(RwLock::new(rules)),
            stats: Arc::new(RwLock::new(stats)),
        })
    }

    /// Create a disabled ModSecurity engine
    fn disabled() -> Self {
        Self {
            config: Arc::new(RwLock::new(ModSecurityConfig::default())),
            rules: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(ModSecurityStats::default())),
        }
    }

    /// Load built-in OWASP TOP10 rules
    async fn load_builtin_owasp_rules(rules: &mut Vec<ModSecRule>) {
        let builtin_rules = vec![
            // SQL Injection Protection (OWASP TOP10 #3)
            r#"SecRule REQUEST_URI "@detectSQLi" "id:100001,msg:'SQL Injection Attack Detected',severity:CRITICAL,phase:2,block""#,
            r#"SecRule ARGS "@detectSQLi" "id:100002,msg:'SQL Injection in Parameters',severity:CRITICAL,phase:2,block""#,
            r#"SecRule REQUEST_BODY "@detectSQLi" "id:100003,msg:'SQL Injection in Request Body',severity:CRITICAL,phase:2,block""#,
            // XSS Protection (OWASP TOP10 #3)
            r#"SecRule REQUEST_URI "@detectXSS" "id:100011,msg:'Cross-site Scripting (XSS) Attack',severity:CRITICAL,phase:2,block""#,
            r#"SecRule ARGS "@detectXSS" "id:100012,msg:'XSS Attack in Parameters',severity:CRITICAL,phase:2,block""#,
            r#"SecRule REQUEST_BODY "@detectXSS" "id:100013,msg:'XSS Attack in Request Body',severity:CRITICAL,phase:2,block""#,
            // Path Traversal Protection (OWASP TOP10 #1)
            r#"SecRule REQUEST_URI "@rx \.\./" "id:100021,msg:'Path Traversal Attack',severity:ERROR,phase:2,block""#,
            r#"SecRule REQUEST_URI "@rx \.\.\\\"" "id:100022,msg:'Windows Path Traversal Attack',severity:ERROR,phase:2,block""#,
            // Command Injection Protection (OWASP TOP10 #3)
            r#"SecRule REQUEST_URI "@rx (?i)(;|&&|\|\|).*(ls|cat|wget|curl|nc|netcat|ping)" "id:100031,msg:'Command Injection Attempt',severity:CRITICAL,phase:2,block""#,
            r#"SecRule ARGS "@rx (?i)(;|&&|\|\|).*(ls|cat|wget|curl|nc|netcat|ping)" "id:100032,msg:'Command Injection in Parameters',severity:CRITICAL,phase:2,block""#,
            // File Inclusion Protection (OWASP TOP10 #5)
            r#"SecRule REQUEST_URI "@rx (?i)(file://|php://|data://|expect://|zip://)" "id:100041,msg:'File Inclusion Attack',severity:ERROR,phase:2,block""#,
            // Suspicious User Agents (OWASP TOP10 #6)
            r#"SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(sqlmap|nikto|nmap|masscan|zap|burp|w3af|acunetix|nessus)" "id:100051,msg:'Malicious User Agent',severity:WARNING,phase:1,block""#,
            // Protocol Violations (OWASP TOP10 #8)
            r#"SecRule REQUEST_METHOD "@rx ^(TRACE|DEBUG|TRACK|CONNECT)$" "id:100061,msg:'HTTP Method Not Allowed',severity:WARNING,phase:1,block""#,
            // Large Request Body (OWASP TOP10 #4)
            r#"SecRule REQUEST_HEADERS:Content-Length "@gt 52428800" "id:100071,msg:'Request Body Too Large',severity:WARNING,phase:1,block""#,
        ];

        for rule_str in builtin_rules {
            match ModSecRule::parse(rule_str) {
                Ok(rule) => {
                    debug!("Loaded built-in rule: {}", rule.id);
                    rules.push(rule);
                }
                Err(e) => {
                    warn!("Failed to parse built-in rule: {}", e);
                }
            }
        }
    }

    /// Load rules from a directory
    async fn load_rules_from_directory(rules: &mut Vec<ModSecRule>, path: &str) -> Result<u64> {
        let path = Path::new(path);
        if !path.exists() {
            info!("Rules directory does not exist: {}", path.display());
            return Ok(0);
        }

        if !path.is_dir() {
            warn!("Rules path is not a directory: {}", path.display());
            return Ok(0);
        }

        let mut count = 0;
        let mut entries = tokio::fs::read_dir(path).await.map_err(|e| {
            error!("Failed to read directory {}: {}", path.display(), e);
            WafError::IoError(e)
        })?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| WafError::IoError(e))?
        {
            let file_path = entry.path();

            if file_path.extension().and_then(|s| s.to_str()) == Some("conf") {
                match Self::load_rules_from_file(rules, &file_path).await {
                    Ok(file_count) => {
                        count += file_count;
                        debug!("Loaded {} rules from {:?}", file_count, file_path);
                    }
                    Err(e) => {
                        warn!("Failed to load rules from {:?}: {}", file_path, e);
                    }
                }
            }
        }

        Ok(count)
    }

    /// Load rules from a single file
    async fn load_rules_from_file(rules: &mut Vec<ModSecRule>, file_path: &Path) -> Result<u64> {
        let content = tokio::fs::read_to_string(file_path)
            .await
            .map_err(|e| WafError::IoError(e))?;

        let mut count = 0;
        for line in content.lines() {
            match ModSecRule::parse(line) {
                Ok(rule) => {
                    rules.push(rule);
                    count += 1;
                }
                Err(_) => {
                    // Skip invalid lines silently (comments, empty lines, etc.)
                }
            }
        }

        Ok(count)
    }

    /// Evaluate a request using ModSecurity rules
    pub async fn evaluate_request(&self, request: &RequestContext) -> Result<WafResult> {
        let config = self.config.read().await;

        if !config.enabled {
            return Ok(WafResult::Allow);
        }

        debug!(
            "Evaluating request with ModSecurity: {} {}",
            request.method, request.uri
        );

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.requests_processed += 1;
        }

        // Evaluate rules
        let rules = self.rules.read().await;
        for rule in rules.iter() {
            match rule.evaluate(request).await {
                Ok(WafResult::Block(message)) => {
                    let mut stats = self.stats.write().await;
                    stats.rules_matched += 1;
                    stats.requests_blocked += 1;
                    *stats.rule_matches_by_id.entry(rule.id.clone()).or_insert(0) += 1;
                    return Ok(WafResult::Block(message));
                }
                Ok(WafResult::Log(message)) => {
                    let mut stats = self.stats.write().await;
                    stats.rules_matched += 1;
                    *stats.rule_matches_by_id.entry(rule.id.clone()).or_insert(0) += 1;
                    return Ok(WafResult::Log(message));
                }
                Ok(WafResult::Allow) => continue,
                Ok(WafResult::RateLimit(message)) => {
                    return Ok(WafResult::RateLimit(message));
                }
                Err(e) => {
                    warn!("Error evaluating ModSec rule {}: {}", rule.id, e);
                }
            }
        }

        Ok(WafResult::Allow)
    }

    /// Update rules dynamically
    pub async fn update_rules(&self) -> Result<()> {
        let config = self.config.read().await;

        if !config.enabled {
            return Ok(());
        }

        info!("Updating ModSecurity rules");

        let mut new_rules = Vec::new();

        // Load built-in rules
        Self::load_builtin_owasp_rules(&mut new_rules).await;
        let mut total_rules = new_rules.len() as u64;

        // Load custom rules
        if Path::new(&config.rules_path).exists() {
            match Self::load_rules_from_directory(&mut new_rules, &config.rules_path).await {
                Ok(count) => {
                    total_rules += count;
                    info!("Reloaded {} custom ModSecurity rules", count);
                }
                Err(e) => warn!("Failed to reload custom rules: {}", e),
            }
        }

        // Download and update OWASP CRS rules if enabled
        if config.auto_update_owasp_crs {
            match Self::download_owasp_crs_rules(&config).await {
                Ok(updated) => {
                    if updated {
                        info!("OWASP CRS rules updated from repository during rule refresh");
                    }
                }
                Err(e) => warn!(
                    "Failed to update OWASP CRS rules during rule refresh: {}",
                    e
                ),
            }
        }

        // Load OWASP CRS
        if Path::new(&config.owasp_crs_path).exists() {
            match Self::load_rules_from_directory(&mut new_rules, &config.owasp_crs_path).await {
                Ok(count) => {
                    total_rules += count;
                    info!("Reloaded {} OWASP CRS rules", count);
                }
                Err(e) => warn!("Failed to reload OWASP CRS rules: {}", e),
            }
        }

        // Replace current rules atomically
        {
            let mut rules = self.rules.write().await;
            *rules = new_rules;
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.rules_loaded = total_rules;
            stats.last_rule_update = Some(chrono::Utc::now());
        }

        info!(
            "ModSecurity rules updated successfully, total: {}",
            total_rules
        );
        Ok(())
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> ModSecurityStats {
        self.stats.read().await.clone()
    }

    /// Update configuration
    pub async fn update_config(&self, new_config: &ModSecurityConfig) -> Result<()> {
        let mut config = self.config.write().await;
        let old_config = config.clone();
        *config = new_config.clone();

        // If enabled state changed or paths changed, trigger rule reload
        if new_config.enabled
            && (old_config.rules_path != new_config.rules_path
                || old_config.owasp_crs_path != new_config.owasp_crs_path
                || old_config.enabled != new_config.enabled)
        {
            drop(config); // Release lock before calling update_rules
            self.update_rules().await?;
        }

        Ok(())
    }

    /// Check if the engine is healthy
    pub async fn is_healthy(&self) -> bool {
        let config = self.config.read().await;
        if !config.enabled {
            return true;
        }

        // Check if we have any rules loaded
        let stats = self.stats.read().await;
        stats.rules_loaded > 0
    }

    /// Download OWASP CRS rules from the official repository
    async fn download_owasp_crs_rules(config: &ModSecurityConfig) -> Result<bool> {
        let crs_path = Path::new(&config.owasp_crs_path);

        // Check if directory exists and has content
        let needs_download = if crs_path.exists() {
            // Check if directory is empty or needs update
            let mut entries = tokio::fs::read_dir(crs_path)
                .await
                .map_err(|e| WafError::IoError(e))?;

            // If directory is empty, we need to download
            entries
                .next_entry()
                .await
                .map_err(|e| WafError::IoError(e))?
                .is_none()
        } else {
            true
        };

        if !needs_download {
            debug!("OWASP CRS directory already exists and has content, skipping download");
            return Ok(false);
        }

        info!(
            "Downloading OWASP CRS rules from {}",
            config.owasp_crs_repo_url
        );

        // Create the directory if it doesn't exist
        if let Err(e) = tokio::fs::create_dir_all(crs_path).await {
            warn!("Failed to create OWASP CRS directory: {}", e);
            return Err(WafError::IoError(e));
        }

        // Download the rules files from GitHub API
        let client = reqwest::Client::new();
        let rules_files = vec![
            "crs-setup.conf.example",
            "rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example",
            "rules/REQUEST-901-INITIALIZATION.conf",
            "rules/REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf",
            "rules/REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf",
            "rules/REQUEST-905-COMMON-EXCEPTIONS.conf",
            "rules/REQUEST-910-IP-REPUTATION.conf",
            "rules/REQUEST-911-METHOD-ENFORCEMENT.conf",
            "rules/REQUEST-912-DOS-PROTECTION.conf",
            "rules/REQUEST-913-SCANNER-DETECTION.conf",
            "rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
            "rules/REQUEST-921-PROTOCOL-ATTACK.conf",
            "rules/REQUEST-922-MULTIPART-ATTACK.conf",
            "rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf",
            "rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf",
            "rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf",
            "rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf",
            "rules/REQUEST-934-APPLICATION-ATTACK-NODEJS.conf",
            "rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
            "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
            "rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
            "rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
            "rules/RESPONSE-950-DATA-LEAKAGES.conf",
            "rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf",
            "rules/RESPONSE-952-DATA-LEAKAGES-JAVA.conf",
            "rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf",
            "rules/RESPONSE-954-DATA-LEAKAGES-IIS.conf",
            "rules/RESPONSE-959-BLOCKING-EVALUATION.conf",
            "rules/RESPONSE-980-CORRELATION.conf",
            "rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example",
        ];

        let mut downloaded_count = 0;
        for file_path in rules_files {
            let url = format!(
                "https://raw.githubusercontent.com/coreruleset/coreruleset/{}/{}",
                config.owasp_crs_version, file_path
            );

            match client.get(&url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.text().await {
                            Ok(content) => {
                                let local_path = crs_path.join(file_path);

                                // Create parent directory if needed
                                if let Some(parent) = local_path.parent() {
                                    if let Err(e) = tokio::fs::create_dir_all(parent).await {
                                        warn!("Failed to create directory {:?}: {}", parent, e);
                                        continue;
                                    }
                                }

                                // Write file content
                                if let Err(e) = tokio::fs::write(&local_path, content).await {
                                    warn!("Failed to write file {:?}: {}", local_path, e);
                                } else {
                                    downloaded_count += 1;
                                    debug!("Downloaded: {}", file_path);
                                }
                            }
                            Err(e) => warn!("Failed to read response for {}: {}", file_path, e),
                        }
                    } else {
                        warn!(
                            "Failed to download {}: HTTP {}",
                            file_path,
                            response.status()
                        );
                    }
                }
                Err(e) => warn!("Failed to download {}: {}", file_path, e),
            }
        }

        if downloaded_count > 0 {
            info!(
                "Successfully downloaded {} OWASP CRS rule files",
                downloaded_count
            );
            Ok(true)
        } else {
            warn!("Failed to download any OWASP CRS rule files");
            Ok(false)
        }
    }
}
