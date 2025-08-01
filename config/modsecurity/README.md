# ModSecurity Configuration Directory

This directory contains ModSecurity rules and configuration files for the Gateway WAF.

## Directory Structure

```
config/modsecurity/
├── README.md              # This file
├── gateway-modsec.conf    # Main ModSecurity configuration
├── owasp-crs/            # OWASP Core Rule Set (CRS) rules
│   ├── crs-setup.conf    # CRS setup configuration
│   └── rules/            # CRS rule files
│       ├── REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
│       ├── REQUEST-901-INITIALIZATION.conf
│       ├── REQUEST-905-COMMON-EXCEPTIONS.conf
│       ├── REQUEST-910-IP-REPUTATION.conf
│       ├── REQUEST-911-METHOD-ENFORCEMENT.conf
│       ├── REQUEST-913-SCANNER-DETECTION.conf
│       ├── REQUEST-920-PROTOCOL-ENFORCEMENT.conf
│       ├── REQUEST-921-PROTOCOL-ATTACK.conf
│       ├── REQUEST-930-APPLICATION-ATTACK-LFI.conf
│       ├── REQUEST-931-APPLICATION-ATTACK-RFI.conf
│       ├── REQUEST-932-APPLICATION-ATTACK-RCE.conf
│       ├── REQUEST-933-APPLICATION-ATTACK-PHP.conf
│       ├── REQUEST-934-APPLICATION-ATTACK-NODEJS.conf
│       ├── REQUEST-941-APPLICATION-ATTACK-XSS.conf
│       ├── REQUEST-942-APPLICATION-ATTACK-SQLI.conf
│       ├── REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
│       ├── REQUEST-944-APPLICATION-ATTACK-JAVA.conf
│       ├── RESPONSE-950-DATA-LEAKAGES.conf
│       ├── RESPONSE-951-DATA-LEAKAGES-SQL.conf
│       ├── RESPONSE-952-DATA-LEAKAGES-JAVA.conf
│       ├── RESPONSE-953-DATA-LEAKAGES-PHP.conf
│       ├── RESPONSE-954-DATA-LEAKAGES-IIS.conf
│       └── RESPONSE-959-BLOCKING-EVALUATION.conf
└── custom/               # Custom rules directory
    ├── 100-custom-allow.conf
    ├── 200-custom-blocks.conf
    └── 300-application-specific.conf
```

## Quick Start

1. **Enable ModSecurity in gateway.yaml**:
```yaml
waf:
  enabled: true
  modsecurity:
    enabled: true
    rules_path: "config/modsecurity/custom"
    owasp_crs_path: "config/modsecurity/owasp-crs"
    blocking_mode: true
    rule_update_interval: 300
    # Dynamic OWASP CRS updates (NEW)
    auto_update_owasp_crs: true
    owasp_crs_repo_url: "https://github.com/coreruleset/coreruleset"
    owasp_crs_version: "v4.3.0"
```

2. **Create the directory structure**:
```bash
mkdir -p config/modsecurity/{custom,owasp-crs/rules}
```

3. **OWASP CRS Rules** - Choose one option:

   **Option A: Automatic Download (Recommended)**
   The gateway will automatically download OWASP CRS rules on startup when `auto_update_owasp_crs: true`.
   
   **Option B: Manual Download**:
   ```bash
   cd config/modsecurity
   wget https://github.com/coreruleset/coreruleset/archive/v4.3.0.tar.gz
   tar -xzf v4.3.0.tar.gz
   mv coreruleset-4.3.0/* owasp-crs/
   ```

## Built-in Rules

The Gateway includes built-in ModSecurity-compatible rules that cover the OWASP TOP 10:

1. **SQL Injection Protection** (A03:2021 – Injection)
2. **Cross-Site Scripting (XSS)** (A03:2021 – Injection) 
3. **Path Traversal** (A01:2021 – Broken Access Control)
4. **Command Injection** (A03:2021 – Injection)
5. **File Inclusion** (A05:2021 – Security Misconfiguration)
6. **Malicious User Agents** (A06:2021 – Vulnerable Components)
7. **Protocol Violations** (A08:2021 – Software/Data Integrity Failures)
8. **Large Request Bodies** (A04:2021 – Insecure Design)

## Rule Syntax

The Gateway supports a subset of ModSecurity rule syntax:

```
SecRule VARIABLES "OPERATOR" "ACTIONS"
```

### Supported Variables:
- `REQUEST_URI` - Request URI/path
- `ARGS` - Query parameters  
- `REQUEST_HEADERS` - All request headers
- `REQUEST_HEADERS:HeaderName` - Specific header
- `REQUEST_BODY` - Request body content
- `REQUEST_METHOD` - HTTP method

### Supported Operators:
- `@rx <regex>` - Regular expression matching
- `@detectSQLi` - Built-in SQL injection detection
- `@detectXSS` - Built-in XSS detection
- `@contains <string>` - String contains
- `@beginsWith <string>` - String starts with
- `@endsWith <string>` - String ends with
- `@eq <string>` - String equals
- `@gt <number>` - Greater than (numeric)
- `@lt <number>` - Less than (numeric)

### Supported Actions:
- `id:<rule_id>` - Rule identifier
- `msg:'<message>'` - Log message
- `severity:<level>` - EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE
- `phase:<1-5>` - Processing phase
- `block` - Block the request
- `deny` - Block the request
- `drop` - Block the request
- `allow` - Allow the request
- `pass` - Allow the request
- `log` - Log only

## Example Rules

### Custom SQL Injection Rule
```
SecRule ARGS "@rx (?i)(union\s+select|drop\s+table)" "id:100001,msg:'SQL Injection Detected',severity:CRITICAL,phase:2,block"
```

### Custom XSS Protection
```
SecRule REQUEST_URI "@rx (?i)<script.*?>.*?</script>" "id:100002,msg:'XSS Attack Detected',severity:CRITICAL,phase:2,block"
```

### Rate Limiting by User Agent
```
SecRule REQUEST_HEADERS:User-Agent "@contains bot" "id:100003,msg:'Bot Traffic Detected',severity:NOTICE,phase:1,log"
```

## Dynamic Rule Updates

The Gateway supports multiple methods for updating ModSecurity rules:

### 1. Automatic OWASP CRS Updates (NEW)

Configure automatic updates from the official OWASP CRS repository:

```yaml
waf:
  modsecurity:
    auto_update_owasp_crs: true
    owasp_crs_repo_url: "https://github.com/coreruleset/coreruleset"
    owasp_crs_version: "v4.3.0"  # or "main" for latest
    rule_update_interval: 3600    # Check every hour
```

**Features:**
- Downloads rules directly from the official GitHub repository
- Supports specific versions or latest release
- Automatic updates during gateway startup
- Periodic updates based on `rule_update_interval`
- No need to commit rule files to your repository

**Benefits:**
- Always up-to-date with latest security rules
- Reduces repository size (no committed rule files)
- Centralized rule management
- Easy version upgrades

### 2. Manual Rule Updates

Rules can be updated manually without restarting the gateway:

**Via Configuration Update**:
```bash
# Update configuration file and reload
kill -HUP <gateway_pid>
```

**Via API** (if enabled):
```bash
curl -X POST http://localhost:9090/api/v1/waf/reload-rules
```

### 3. Container Build Integration

For containerized deployments, you can choose between:

**Option A: Runtime Download (Recommended)**
```dockerfile
# Dockerfile
FROM your-base-image
COPY config/gateway.yaml /app/config/
# Rules will be downloaded at runtime
```

**Option B: Build-time Download**
```dockerfile
# Dockerfile
FROM your-base-image
RUN mkdir -p /app/config/modsecurity/owasp-crs && \
    wget -O- https://github.com/coreruleset/coreruleset/archive/v4.3.0.tar.gz | \
    tar -xz -C /app/config/modsecurity/owasp-crs --strip-components=1
```

## Monitoring and Logging

ModSecurity events are logged with structured JSON format:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "WARN",
  "message": "ModSecurity rule 100001 triggered: SQL Injection Detected",
  "rule_id": "100001",
  "client_ip": "192.168.1.100",
  "request_uri": "/api/users?id=1' OR '1'='1",
  "action": "blocked"
}
```

## Performance Considerations

- **Rule Ordering**: Place more specific rules first for better performance
- **Regex Optimization**: Use efficient regex patterns to avoid ReDoS
- **Body Inspection**: Limit `max_body_size` for large file uploads
- **Selective Enabling**: Disable rules for trusted sources when appropriate

## Troubleshooting

### Rule Not Triggering
1. Check rule syntax in logs
2. Verify rule is enabled  
3. Test regex patterns independently
4. Check phase ordering

### False Positives
1. Add exceptions in EXCLUSION rules
2. Adjust rule sensitivity
3. Use whitelist for trusted sources
4. Tune regex patterns

### Performance Issues
1. Profile rule execution times
2. Optimize expensive regex patterns
3. Limit body inspection size
4. Use caching for repeated patterns

## Security Best Practices

1. **Regular Updates**: Keep OWASP CRS updated to latest version
2. **Custom Rules**: Add application-specific rules for better protection
3. **Monitoring**: Set up alerts for rule triggers
4. **Testing**: Test rules in non-blocking mode first
5. **Documentation**: Document all custom rules and exceptions

## References

- [OWASP ModSecurity Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/)
- [ModSecurity Reference Manual](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)