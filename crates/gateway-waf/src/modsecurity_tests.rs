//! Integration tests for ModSecurity functionality

#[cfg(test)]
mod tests {
    use crate::{ModSecurityConfig, ModSecurityEngine, RequestContext, WafResult};
    use std::collections::HashMap;
    use std::net::IpAddr;

    async fn create_test_engine() -> ModSecurityEngine {
        let config = ModSecurityConfig {
            enabled: true,
            rules_path: "test_rules".to_string(),
            owasp_crs_path: "test_crs".to_string(),
            debug_log_level: 3,
            max_body_size: 1024,
            blocking_mode: true,
            rule_update_interval: 300,
        };
        
        ModSecurityEngine::new(&config).await.expect("Failed to create ModSecurity engine")
    }

    fn create_test_request(uri: &str, method: &str) -> RequestContext {
        let mut query_params = HashMap::new();
        
        // Parse query parameters from URI
        if let Some(query_start) = uri.find('?') {
            let query_string = &uri[query_start + 1..];
            for param in query_string.split('&') {
                if let Some(eq_pos) = param.find('=') {
                    let key = &param[..eq_pos];
                    let value = &param[eq_pos + 1..];
                    query_params.insert(key.to_string(), value.to_string());
                }
            }
        }
        
        RequestContext {
            method: method.to_string(),
            uri: uri.to_string(),
            headers: HashMap::new(),
            query_params,
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            user_agent: Some("TestAgent/1.0".to_string()),
            content_type: Some("application/json".to_string()),
            content_length: Some(100),
            body: None,
        }
    }

    #[tokio::test]
    async fn test_disabled_modsecurity_allows_all() {
        let config = ModSecurityConfig {
            enabled: false,
            ..Default::default()
        };
        
        let engine = ModSecurityEngine::new(&config).await.unwrap();
        let request = create_test_request("/test", "GET");
        
        let result = engine.evaluate_request(&request).await.unwrap();
        assert!(matches!(result, WafResult::Allow));
    }

    #[tokio::test]
    async fn test_sql_injection_detection() {
        let engine = create_test_engine().await;
        
        // Test SQL injection in URI
        let request = create_test_request("/api/users?id=1' OR '1'='1", "GET");
        let result = engine.evaluate_request(&request).await.unwrap();
        
        println!("SQL injection test result: {:?}", result);
        
        match result {
            WafResult::Block(message) => {
                assert!(message.contains("SQL") || message.contains("injection") || message.contains("100002"));
            }
            WafResult::Log(message) => {
                assert!(message.contains("SQL") || message.contains("injection") || message.contains("100002"));
            }
            _ => panic!("Expected SQL injection to be detected, got: {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_xss_detection() {
        let engine = create_test_engine().await;
        
        // Test XSS in URI
        let request = create_test_request("/search?q=<script>alert('xss')</script>", "GET");
        let result = engine.evaluate_request(&request).await.unwrap();
        
        match result {
            WafResult::Block(message) => {
                assert!(message.contains("XSS") || message.contains("script"));
            }
            _ => panic!("Expected XSS attack to be blocked"),
        }
    }

    #[tokio::test]
    async fn test_path_traversal_detection() {
        let engine = create_test_engine().await;
        
        // Test path traversal
        let request = create_test_request("/files?path=../../../etc/passwd", "GET");
        let result = engine.evaluate_request(&request).await.unwrap();
        
        match result {
            WafResult::Block(message) => {
                assert!(message.contains("Path Traversal") || message.contains("traversal"));
            }
            _ => panic!("Expected path traversal to be blocked"),
        }
    }

    #[tokio::test]
    async fn test_malicious_user_agent_detection() {
        let engine = create_test_engine().await;
        
        let mut request = create_test_request("/", "GET");
        request.headers.insert("User-Agent".to_string(), "sqlmap/1.0".to_string());
        
        let result = engine.evaluate_request(&request).await.unwrap();
        
        match result {
            WafResult::Block(message) => {
                assert!(message.contains("Malicious") || message.contains("User Agent"));
            }
            _ => panic!("Expected malicious user agent to be blocked"),
        }
    }

    #[tokio::test]
    async fn test_legitimate_request_allowed() {
        let engine = create_test_engine().await;
        
        let request = create_test_request("/api/users", "GET");
        let result = engine.evaluate_request(&request).await.unwrap();
        
        println!("Legitimate request result: {:?}", result);
        
        // Accept both Allow and Log results for legitimate requests
        match result {
            WafResult::Allow | WafResult::Log(_) => {
                // This is expected for legitimate requests
            }
            _ => panic!("Expected legitimate request to be allowed or logged, got: {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_command_injection_detection() {
        let engine = create_test_engine().await;
        
        // Test command injection in query parameters
        let mut request = create_test_request("/api/system", "GET");
        request.query_params.insert("cmd".to_string(), "; ls -la".to_string());
        
        let result = engine.evaluate_request(&request).await.unwrap();
        
        match result {
            WafResult::Block(message) => {
                assert!(message.contains("Command") || message.contains("injection"));
            }
            _ => panic!("Expected command injection to be blocked"),
        }
    }

    #[tokio::test]
    async fn test_rule_statistics() {
        let engine = create_test_engine().await;
        
        // Generate some test requests
        let requests = vec![
            create_test_request("/api/users?id=1' OR '1'='1", "GET"), // SQL injection
            create_test_request("/search?q=<script>alert(1)</script>", "GET"), // XSS
            create_test_request("/api/users", "GET"), // Legitimate request
        ];
        
        for request in requests {
            let _ = engine.evaluate_request(&request).await;
        }
        
        let stats = engine.get_stats().await;
        assert_eq!(stats.requests_processed, 3);
        assert!(stats.rules_loaded > 0);
        // At least 2 requests should be blocked (SQL injection and XSS)
        assert!(stats.requests_blocked >= 2);
    }

    #[tokio::test]
    async fn test_rule_update() {
        let engine = create_test_engine().await;
        
        // Get initial stats
        let stats_before = engine.get_stats().await;
        
        // Update rules
        engine.update_rules().await.expect("Failed to update rules");
        
        // Get updated stats
        let stats_after = engine.get_stats().await;
        
        // Should have updated timestamp
        assert!(stats_after.last_rule_update > stats_before.last_rule_update);
    }

    #[tokio::test]
    async fn debug_rule_parsing() {
        use crate::modsecurity_engine::ModSecRule;
        
        // Test parsing a simple rule
        let rule_str = r#"SecRule ARGS "@detectSQLi" "id:100002,msg:'SQL Injection in Parameters',severity:CRITICAL,phase:2,block""#;
        
        match ModSecRule::parse(rule_str) {
            Ok(rule) => {
                println!("Parsed rule: ID={}, Variables={:?}, Operator={}, Actions={:?}", 
                         rule.id, rule.variables, rule.operator, rule.actions);
            }
            Err(e) => {
                println!("Failed to parse rule: {}", e);
            }
        }
    }
}