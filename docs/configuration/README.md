# Configuration Reference

This document provides comprehensive information about configuring the Gateway.

## Configuration File Format

Gateway uses YAML configuration files. The default configuration file is `config/gateway.yaml`.

### Environment Variable Substitution

Configuration values can reference environment variables using the `${VAR_NAME}` syntax:

```yaml
database:
  url: "${DATABASE_URL}"
auth:
  jwt_secret: "${JWT_SECRET}"
```

## Configuration Sections

### Server Configuration

```yaml
server:
  bind_address: "0.0.0.0:8080"     # Listen address
  worker_threads: 4                 # Number of worker threads
  debug: false                      # Enable debug mode
  max_connections: 10000            # Maximum concurrent connections
  connection_timeout: "30s"         # Connection timeout
  keep_alive_timeout: "60s"         # Keep-alive timeout
  graceful_shutdown_timeout: "30s"  # Graceful shutdown timeout
  
  # TLS configuration (optional)
  tls:
    cert_path: "certs/server.crt"
    key_path: "certs/server.key"
    ca_path: "certs/ca.crt"         # Optional CA certificate
    require_client_cert: false      # Require client certificates
```

### WAF Configuration

```yaml
waf:
  enabled: true                     # Enable/disable WAF
  rules_path: "config/waf-rules.yaml"  # Path to WAF rules file
  
  # Rate limiting configuration
  rate_limiting:
    enabled: true
    requests_per_minute: 1000       # Requests per minute per key
    burst_limit: 100                # Burst limit
    window_size: "60s"              # Time window
    storage_backend: "memory"       # "memory", "redis", "database"
  
  # IP filtering
  ip_whitelist:                     # Allowed IP addresses/CIDR ranges
    - "127.0.0.1"
    - "192.168.1.0/24"
  ip_blacklist:                     # Blocked IP addresses/CIDR ranges
    - "10.0.0.1"
    - "172.16.0.0/12"
  
  # Header filtering
  blocked_headers:                  # Headers that trigger blocking
    - "X-Malicious-Header"
  blocked_user_agents:              # User agents that trigger blocking
    - "BadBot/1.0"
    - "MaliciousScanner"
  
  max_request_size: 10485760        # Maximum request size (10MB)
  block_malicious_ips: true         # Block known malicious IPs
```

### Cache Configuration

```yaml
cache:
  enabled: true                     # Enable/disable caching
  backend: "memory"                 # "memory", "redis", "distributed"
  ttl: "300s"                       # Default time-to-live
  max_size: 104857600               # Maximum cache size (100MB)
  compression: true                 # Enable compression
  
  # Redis configuration (when backend is "redis")
  redis:
    url: "redis://localhost:6379"
    pool_size: 10
    timeout: "5s"
    cluster: false                  # Enable Redis Cluster support
```

### Database Configuration

```yaml
database:
  enabled: false                    # Enable/disable database
  backend: "postgres"               # "postgres", "mysql", "mongodb", "dynamodb", "firebase"
  url: "${DATABASE_URL}"            # Connection string
  pool_size: 10                     # Connection pool size
  timeout: "30s"                    # Query timeout
  migrations_path: "migrations"     # Path to migration files
  ssl_mode: "prefer"                # SSL mode for PostgreSQL
```

#### Backend-specific Configuration

**PostgreSQL/MySQL:**
```yaml
database:
  backend: "postgres"
  url: "postgresql://user:password@localhost:5432/gateway"
  ssl_mode: "require"  # "disable", "allow", "prefer", "require"
```

**MongoDB:**
```yaml
database:
  backend: "mongodb"
  url: "mongodb://localhost:27017/gateway"
```

**DynamoDB:**
```yaml
database:
  backend: "dynamodb"
  url: "region=us-east-1,table_prefix=gateway"
```

### Authentication Configuration

```yaml
auth:
  enabled: false                    # Enable/disable authentication
  jwt_secret: "${JWT_SECRET}"       # JWT signing secret
  jwt_expiry: "3600s"               # JWT expiration time
  require_auth: false               # Require authentication for all requests
  
  # Public paths (no authentication required)
  public_paths:
    - "/health"
    - "/metrics"
    - "/api/public"
  
  # Authentication providers
  providers:
    jwt:
      type: "jwt"
      config:
        algorithm: "HS256"
    oauth2:
      type: "oauth2"
      config:
        client_id: "${OAUTH2_CLIENT_ID}"
        client_secret: "${OAUTH2_CLIENT_SECRET}"
        auth_url: "https://auth.example.com/oauth2/authorize"
        token_url: "https://auth.example.com/oauth2/token"
```

### Monitoring Configuration

```yaml
monitoring:
  enabled: true                     # Enable/disable monitoring
  metrics_port: 9090                # Metrics server port
  log_level: "info"                 # Log level: "trace", "debug", "info", "warn", "error"
  health_check_path: "/health"      # Health check endpoint path
  
  # Prometheus metrics
  prometheus:
    enabled: true
    endpoint: "/metrics"            # Metrics endpoint path
    namespace: "gateway"            # Metrics namespace
  
  # Distributed tracing
  tracing:
    enabled: false
    endpoint: "http://localhost:14268/api/traces"  # Jaeger endpoint
    sample_rate: 0.1                # Sampling rate (0.0 to 1.0)
```

### Plugin Configuration

```yaml
plugins:
  enabled: false                    # Enable/disable plugins
  plugin_dir: "plugins"             # Plugin directory
  
  # Plugin instances
  plugins:
    auth_plugin:
      enabled: true
      config:
        provider: "ldap"
        server: "ldap://localhost:389"
    
    custom_headers:
      enabled: true
      config:
        headers:
          X-Gateway-Version: "1.0"
          X-Request-ID: "${request.id}"
```

### Upstream Configuration

```yaml
upstream:
  # Backend servers
  backends:
    - name: "api-v1"
      address: "http://api-v1:3000"
      weight: 2                     # Load balancing weight
      health_check_path: "/health"
      max_connections: 100
      timeout: "30s"
    
    - name: "api-v2"
      address: "http://api-v2:3000"
      weight: 1
      health_check_path: "/health"
      max_connections: 100
      timeout: "30s"
  
  # Load balancing configuration
  load_balancing:
    algorithm: "round_robin"        # "round_robin", "least_connections", "ip_hash", "weighted"
    sticky_sessions: false          # Enable sticky sessions
    session_cookie: "JSESSIONID"    # Session cookie name
  
  # Health check configuration
  health_check:
    enabled: true
    interval: "30s"                 # Health check interval
    timeout: "5s"                   # Health check timeout
    retries: 3                      # Number of retries
    path: "/health"                 # Health check path
    expected_status: 200            # Expected HTTP status code
  
  # Circuit breaker configuration
  circuit_breaker:
    enabled: true
    failure_threshold: 5            # Failures before opening circuit
    timeout: "60s"                  # Time before attempting half-open
    half_open_max_calls: 3          # Max calls in half-open state
```

## Configuration Validation

The Gateway validates configuration on startup. Common validation errors:

### Invalid Bind Address
```yaml
# ❌ Invalid
server:
  bind_address: "invalid-address"

# ✅ Valid
server:
  bind_address: "0.0.0.0:8080"
```

### Empty Backend List
```yaml
# ❌ Invalid
upstream:
  backends: []

# ✅ Valid
upstream:
  backends:
    - name: "backend-1"
      address: "http://localhost:3000"
```

### Invalid Duration Format
```yaml
# ❌ Invalid
server:
  connection_timeout: "30"

# ✅ Valid
server:
  connection_timeout: "30s"  # or "5m", "1h", etc.
```

## Configuration Examples

### Development Configuration
```yaml
server:
  bind_address: "127.0.0.1:8080"
  debug: true

waf:
  enabled: false

monitoring:
  log_level: "debug"

upstream:
  backends:
    - name: "local-api"
      address: "http://localhost:3000"
```

### Production Configuration
```yaml
server:
  bind_address: "0.0.0.0:8080"
  worker_threads: 8
  max_connections: 50000
  tls:
    cert_path: "/etc/ssl/certs/gateway.crt"
    key_path: "/etc/ssl/private/gateway.key"

waf:
  enabled: true
  rate_limiting:
    requests_per_minute: 10000
    storage_backend: "redis"

cache:
  enabled: true
  backend: "redis"
  redis:
    url: "${REDIS_URL}"
    cluster: true

database:
  enabled: true
  backend: "postgres"
  url: "${DATABASE_URL}"
  pool_size: 20

auth:
  enabled: true
  jwt_secret: "${JWT_SECRET}"
  require_auth: true

monitoring:
  enabled: true
  tracing:
    enabled: true
    endpoint: "${JAEGER_ENDPOINT}"

upstream:
  backends:
    - name: "api-primary"
      address: "http://api-primary.internal:3000"
      weight: 3
    - name: "api-secondary"
      address: "http://api-secondary.internal:3000"
      weight: 1
  
  load_balancing:
    algorithm: "least_connections"
  
  circuit_breaker:
    enabled: true
    failure_threshold: 10
```

## Dynamic Configuration

Some configuration can be updated at runtime using the management API:

```bash
# Update WAF rules
curl -X POST http://localhost:9090/admin/waf/rules \
  -H "Content-Type: application/json" \
  -d @new-rules.json

# Update upstream backends
curl -X PUT http://localhost:9090/admin/upstream/backends \
  -H "Content-Type: application/json" \
  -d '[{"name": "new-backend", "address": "http://new-backend:3000"}]'

# Reload configuration
curl -X POST http://localhost:9090/admin/config/reload
```

## Best Practices

1. **Use Environment Variables**: Store sensitive data in environment variables
2. **Validate Configuration**: Always test configuration changes in a staging environment
3. **Monitor Configuration**: Track configuration changes and their impact
4. **Backup Configuration**: Keep backups of working configurations
5. **Version Control**: Store configuration files in version control
6. **Security**: Protect configuration files with appropriate file permissions

## Troubleshooting

### Configuration Not Loading
- Check file permissions
- Verify YAML syntax
- Check for environment variable availability

### Performance Issues
- Adjust worker thread count based on CPU cores
- Tune connection limits and timeouts
- Enable caching for static content

### Security Concerns
- Enable WAF in production
- Use TLS certificates
- Configure rate limiting appropriately
- Review IP whitelist/blacklist regularly