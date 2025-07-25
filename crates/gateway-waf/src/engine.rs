use std::sync::Arc;
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::{WafConfig, WafResult, RequestContext, WafStats, WafError, Result};
use crate::rules::WafRuleSet;
use crate::rate_limiter::RateLimiter;
use crate::ip_filter::IpFilter;
use gateway_database::DatabaseManager;

/// Main WAF engine that evaluates requests against configured rules
pub struct WafEngine {
    config: Arc<RwLock<WafConfig>>,
    rules: Arc<RwLock<WafRuleSet>>,
    rate_limiter: Arc<RateLimiter>,
    ip_filter: Arc<IpFilter>,
    stats: Arc<RwLock<WafStats>>,
    database: Arc<DatabaseManager>,
}

impl WafEngine {
    /// Create a new WAF engine
    pub async fn new(config: &WafConfig, database: Arc<DatabaseManager>) -> Result<Self> {
        info!("Initializing WAF engine");

        let rules = WafRuleSet::load_from_file(&config.rules_path).await
            .unwrap_or_else(|e| {
                warn!("Failed to load WAF rules from {}: {}, using default rules", config.rules_path, e);
                WafRuleSet::default()
            });

        let rate_limiter = Arc::new(RateLimiter::new(&config.rate_limiting, database.clone()).await?);
        let ip_filter = Arc::new(IpFilter::new(&config.ip_whitelist, &config.ip_blacklist));

        Ok(Self {
            config: Arc::new(RwLock::new(config.clone())),
            rules: Arc::new(RwLock::new(rules)),
            rate_limiter,
            ip_filter,
            stats: Arc::new(RwLock::new(WafStats::default())),
            database,
        })
    }

    /// Evaluate a request against WAF rules
    pub async fn evaluate_request(&self, request: &RequestContext) -> Result<WafResult> {
        let config = self.config.read().await;
        
        if !config.enabled {
            return Ok(WafResult::Allow);
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_requests += 1;
        }

        debug!("Evaluating WAF rules for request: {} {}", request.method, request.uri);

        // 1. Check request size
        if let Some(content_length) = request.content_length {
            if content_length as usize > config.max_request_size {
                let mut stats = self.stats.write().await;
                stats.blocked_requests += 1;
                return Ok(WafResult::Block("Request size exceeds limit".to_string()));
            }
        }

        // 2. IP filtering
        match self.ip_filter.check_ip(request.client_ip).await {
            Ok(true) => {}, // IP is allowed
            Ok(false) => {
                let mut stats = self.stats.write().await;
                stats.blocked_requests += 1;
                stats.ip_blocks += 1;
                return Ok(WafResult::Block(format!("IP {} is blocked", request.client_ip)));
            }
            Err(e) => {
                warn!("IP filter error: {}", e);
            }
        }

        // 3. Rate limiting
        match self.rate_limiter.check_request(request).await {
            Ok(true) => {}, // Request is within rate limits
            Ok(false) => {
                let mut stats = self.stats.write().await;
                stats.rate_limited_requests += 1;
                return Ok(WafResult::RateLimit("Rate limit exceeded".to_string()));
            }
            Err(e) => {
                warn!("Rate limiter error: {}", e);
            }
        }

        // 4. Header filtering
        for header_name in &config.blocked_headers {
            if request.headers.contains_key(header_name) {
                let mut stats = self.stats.write().await;
                stats.blocked_requests += 1;
                stats.header_blocks += 1;
                return Ok(WafResult::Block(format!("Blocked header: {}", header_name)));
            }
        }

        // 5. User-Agent filtering
        if let Some(user_agent) = &request.user_agent {
            for blocked_ua in &config.blocked_user_agents {
                if user_agent.contains(blocked_ua) {
                    let mut stats = self.stats.write().await;
                    stats.blocked_requests += 1;
                    stats.header_blocks += 1;
                    return Ok(WafResult::Block(format!("Blocked user agent: {}", blocked_ua)));
                }
            }
        }

        // 6. URL filtering
        if self.is_malicious_url(&request.uri) {
            let mut stats = self.stats.write().await;
            stats.blocked_requests += 1;
            stats.url_blocks += 1;
            return Ok(WafResult::Block("Malicious URL pattern detected".to_string()));
        }

        // 7. Custom rules evaluation
        let rules = self.rules.read().await;
        for rule in &rules.rules {
            match rule.evaluate(request).await {
                Ok(WafResult::Block(reason)) => {
                    let mut stats = self.stats.write().await;
                    stats.blocked_requests += 1;
                    *stats.rule_matches.entry(rule.id.clone()).or_insert(0) += 1;
                    return Ok(WafResult::Block(reason));
                }
                Ok(WafResult::Log(message)) => {
                    info!("WAF rule {} triggered: {}", rule.id, message);
                    let mut stats = self.stats.write().await;
                    *stats.rule_matches.entry(rule.id.clone()).or_insert(0) += 1;
                }
                Ok(WafResult::RateLimit(reason)) => {
                    let mut stats = self.stats.write().await;
                    stats.rate_limited_requests += 1;
                    return Ok(WafResult::RateLimit(reason));
                }
                Ok(WafResult::Allow) => {},
                Err(e) => {
                    warn!("Error evaluating rule {}: {}", rule.id, e);
                }
            }
        }

        debug!("Request passed all WAF checks");
        Ok(WafResult::Allow)
    }

    /// Check if URL contains malicious patterns
    fn is_malicious_url(&self, url: &str) -> bool {
        let malicious_patterns = [
            "../", "..\\",  // Directory traversal
            "<script", "</script>", // XSS
            "union select", "drop table", "delete from", // SQL injection
            "javascript:", "vbscript:", // Script injection
            "%3Cscript", "%3C%2Fscript%3E", // Encoded XSS
            "eval(", "exec(", // Code execution
        ];

        let url_lower = url.to_lowercase();
        malicious_patterns.iter().any(|&pattern| url_lower.contains(pattern))
    }

    /// Get current WAF statistics
    pub async fn get_stats(&self) -> WafStats {
        self.stats.read().await.clone()
    }

    /// Update WAF configuration
    pub async fn update_config(&self, new_config: &WafConfig) -> Result<()> {
        info!("Updating WAF configuration");

        let mut config = self.config.write().await;
        *config = new_config.clone();

        // Reload rules if the rules path changed
        if config.rules_path != new_config.rules_path {
            let new_rules = WafRuleSet::load_from_file(&new_config.rules_path).await
                .unwrap_or_else(|e| {
                    warn!("Failed to load new WAF rules: {}", e);
                    WafRuleSet::default()
                });
            
            let mut rules = self.rules.write().await;
            *rules = new_rules;
        }

        // Update rate limiter if needed
        if config.rate_limiting != new_config.rate_limiting {
            if let Err(e) = self.rate_limiter.update_config(&new_config.rate_limiting).await {
                warn!("Failed to update rate limiter config: {}", e);
            }
        }

        // Update IP filter
        self.ip_filter.update_lists(&new_config.ip_whitelist, &new_config.ip_blacklist).await;

        info!("WAF configuration updated successfully");
        Ok(())
    }

    /// Check if WAF is healthy
    pub async fn is_healthy(&self) -> bool {
        // Check if all components are functioning
        self.rate_limiter.is_healthy().await && self.ip_filter.is_healthy().await
    }

    /// Reload WAF rules from file
    pub async fn reload_rules(&self) -> Result<()> {
        let config = self.config.read().await;
        
        let new_rules = WafRuleSet::load_from_file(&config.rules_path).await?;
        
        let mut rules = self.rules.write().await;
        *rules = new_rules;
        
        info!("WAF rules reloaded successfully");
        Ok(())
    }

    /// Add a custom rule at runtime
    pub async fn add_rule(&self, rule: crate::rules::WafRule) -> Result<()> {
        let mut rules = self.rules.write().await;
        rules.add_rule(rule);
        info!("Custom WAF rule added");
        Ok(())
    }

    /// Remove a rule by ID
    pub async fn remove_rule(&self, rule_id: &str) -> Result<bool> {
        let mut rules = self.rules.write().await;
        let removed = rules.remove_rule(rule_id);
        if removed {
            info!("WAF rule {} removed", rule_id);
        }
        Ok(removed)
    }
}