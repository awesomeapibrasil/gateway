# Ingress Controller Annotations

This document describes the annotations supported by the Gateway Ingress Controller for configuring backend behavior, plugins, and other advanced features.

## Overview

The Gateway Ingress Controller uses annotations to configure additional behavior that goes beyond the standard Kubernetes Ingress specification. All annotations use the `gateway.awesomeapi.com.br/` prefix.

## Supported Annotations

### Backend Protocol

**Annotation:** `gateway.awesomeapi.com.br/backend-protocol`

**Description:** Specifies the protocol to use when communicating with the backend service.

**Supported Values:**
- `http` (default) - HTTP protocol
- `https` - HTTPS protocol with TLS
- `grpc` - gRPC protocol over HTTP/2
- `grpc-secure` or `grpcs` - gRPC protocol over HTTP/2 with TLS
- `websocket` or `ws` - WebSocket protocol
- `websocket-secure` or `wss` - WebSocket protocol with TLS

**Example:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grpc-service
  annotations:
    gateway.awesomeapi.com.br/backend-protocol: "grpc"
spec:
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: grpc-service
            port:
              number: 50051
```

### SSL Redirect

**Annotation:** `gateway.awesomeapi.com.br/ssl-redirect`

**Description:** Automatically redirect HTTP requests to HTTPS.

**Supported Values:**
- `true` - Enable SSL redirect
- `false` (default) - Disable SSL redirect

**Example:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-app
  annotations:
    gateway.awesomeapi.com.br/ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - secure.example.com
  rules:
  - host: secure.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-service
            port:
              number: 80
```

### Rate Limiting

**Annotation:** `gateway.awesomeapi.com.br/rate-limit`

**Description:** Configure rate limiting for the ingress route.

**Format:** JSON object with the following fields:
- `requests_per_minute` (required): Maximum requests per minute
- `burst` (optional): Burst allowance
- `key` (optional): Rate limiting key (`ip`, `header:X-Header-Name`, `jwt:claim`)

**Example:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rate-limited-api
  annotations:
    gateway.awesomeapi.com.br/rate-limit: |
      {
        "requests_per_minute": 100,
        "burst": 20,
        "key": "ip"
      }
spec:
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 8080
```

### Authentication

**Annotation:** `gateway.awesomeapi.com.br/auth-type`

**Description:** Configure authentication for the ingress route.

**Format:** JSON object with the following fields:
- `auth_type` (required): Authentication type (`basic`, `jwt`, `oauth2`, `ldap`)
- `realm` (optional): Authentication realm
- `auth_url` (optional): External authentication URL
- `auth_headers` (optional): Headers to pass to authentication service

**Example:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: protected-app
  annotations:
    gateway.awesomeapi.com.br/auth-type: |
      {
        "auth_type": "jwt",
        "realm": "example.com"
      }
spec:
  rules:
  - host: private.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: private-service
            port:
              number: 80
```

### Plugins

**Annotation:** `gateway.awesomeapi.com.br/plugins`

**Description:** Configure plugins to be applied to the ingress route.

**Format:** JSON array of plugin objects with the following fields:
- `name` (required): Plugin name
- `enabled` (required): Whether the plugin is enabled
- `config` (optional): Plugin-specific configuration

**Example:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-with-plugins
  annotations:
    gateway.awesomeapi.com.br/plugins: |
      [
        {
          "name": "request-logging",
          "enabled": true,
          "config": {
            "level": "info",
            "include_headers": true
          }
        },
        {
          "name": "response-transform",
          "enabled": true,
          "config": {
            "add_headers": {
              "X-Powered-By": "Gateway"
            }
          }
        }
      ]
spec:
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-service
            port:
              number: 80
```

### Upstream Timeout

**Annotation:** `gateway.awesomeapi.com.br/upstream-timeout`

**Description:** Configure timeout for upstream requests in seconds.

**Example:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: slow-service
  annotations:
    gateway.awesomeapi.com.br/upstream-timeout: "60"
spec:
  rules:
  - host: slow.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: slow-service
            port:
              number: 80
```

### Load Balancer

**Annotation:** `gateway.awesomeapi.com.br/load-balancer`

**Description:** Configure load balancing behavior.

**Format:** JSON object with the following fields:
- `algorithm` (required): Load balancing algorithm (`round_robin`, `least_connections`, `ip_hash`, `weighted`)
- `sticky_sessions` (optional): Enable sticky sessions
- `health_check` (optional): Enable health checks

**Example:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: load-balanced-app
  annotations:
    gateway.awesomeapi.com.br/load-balancer: |
      {
        "algorithm": "least_connections",
        "sticky_sessions": true,
        "health_check": true
      }
spec:
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-service
            port:
              number: 80
```

### Circuit Breaker

**Annotation:** `gateway.awesomeapi.com.br/circuit-breaker`

**Description:** Configure circuit breaker for upstream services.

**Format:** JSON object with the following fields:
- `enabled` (required): Enable circuit breaker
- `failure_threshold` (required): Number of failures to trigger circuit breaker
- `timeout_seconds` (required): Timeout before attempting to close circuit
- `half_open_max_calls` (required): Maximum calls in half-open state

**Example:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: resilient-app
  annotations:
    gateway.awesomeapi.com.br/circuit-breaker: |
      {
        "enabled": true,
        "failure_threshold": 5,
        "timeout_seconds": 30,
        "half_open_max_calls": 3
      }
spec:
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-service
            port:
              number: 80
```

### CORS

**Annotation:** `gateway.awesomeapi.com.br/cors`

**Description:** Configure Cross-Origin Resource Sharing (CORS) headers.

**Format:** JSON object with the following fields:
- `enabled` (required): Enable CORS
- `allowed_origins` (required): List of allowed origins
- `allowed_methods` (required): List of allowed HTTP methods
- `allowed_headers` (optional): List of allowed headers
- `exposed_headers` (optional): List of headers to expose
- `max_age` (optional): Cache duration for preflight requests
- `allow_credentials` (optional): Allow credentials

**Example:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cors-enabled-api
  annotations:
    gateway.awesomeapi.com.br/cors: |
      {
        "enabled": true,
        "allowed_origins": ["https://app.example.com", "https://admin.example.com"],
        "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
        "allowed_headers": ["Content-Type", "Authorization"],
        "exposed_headers": ["X-Request-ID"],
        "max_age": 3600,
        "allow_credentials": true
      }
spec:
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 8080
```

### Compression

**Annotation:** `gateway.awesomeapi.com.br/compression`

**Description:** Configure response compression.

**Format:** JSON object with the following fields:
- `enabled` (required): Enable compression
- `algorithms` (optional): List of compression algorithms (`gzip`, `brotli`, `deflate`)
- `min_size` (optional): Minimum response size to compress (bytes)
- `types` (optional): List of MIME types to compress

**Example:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: compressed-content
  annotations:
    gateway.awesomeapi.com.br/compression: |
      {
        "enabled": true,
        "algorithms": ["brotli", "gzip"],
        "min_size": 1024,
        "types": ["text/html", "application/json", "text/css", "application/javascript"]
      }
spec:
  rules:
  - host: static.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: static-service
            port:
              number: 80
```

## Complete Example

Here's a comprehensive example using multiple annotations:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: full-featured-app
  annotations:
    gateway.awesomeapi.com.br/backend-protocol: "https"
    gateway.awesomeapi.com.br/ssl-redirect: "true"
    gateway.awesomeapi.com.br/rate-limit: |
      {
        "requests_per_minute": 1000,
        "burst": 100,
        "key": "ip"
      }
    gateway.awesomeapi.com.br/auth-type: |
      {
        "auth_type": "jwt",
        "realm": "example.com"
      }
    gateway.awesomeapi.com.br/plugins: |
      [
        {
          "name": "request-logging",
          "enabled": true,
          "config": {"level": "info"}
        }
      ]
    gateway.awesomeapi.com.br/upstream-timeout: "30"
    gateway.awesomeapi.com.br/load-balancer: |
      {
        "algorithm": "round_robin",
        "sticky_sessions": false,
        "health_check": true
      }
    gateway.awesomeapi.com.br/circuit-breaker: |
      {
        "enabled": true,
        "failure_threshold": 5,
        "timeout_seconds": 60,
        "half_open_max_calls": 3
      }
    gateway.awesomeapi.com.br/cors: |
      {
        "enabled": true,
        "allowed_origins": ["https://app.example.com"],
        "allowed_methods": ["GET", "POST"],
        "allow_credentials": true
      }
    gateway.awesomeapi.com.br/compression: |
      {
        "enabled": true,
        "algorithms": ["brotli", "gzip"],
        "min_size": 1024
      }
spec:
  tls:
  - hosts:
    - app.example.com
    secretName: app-tls
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 443
      - path: /static
        pathType: Prefix
        backend:
          service:
            name: static-service
            port:
              number: 80
```

## Auto-SSL Integration

When auto-SSL is enabled, the ingress controller automatically provisions TLS certificates for ingresses with TLS configuration. No additional annotations are required - simply define the TLS section in your ingress:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auto-ssl-example
spec:
  tls:
  - hosts:
    - auto.example.com
    - www.auto.example.com
  rules:
  - host: auto.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-service
            port:
              number: 80
```

The ingress controller will automatically:
1. Request certificates from Let's Encrypt (or configured ACME provider)
2. Store certificates in the configured storage backend (database or Vault)
3. Load certificates into memory for fast serving
4. Automatically renew certificates before expiration
5. Watch for external certificate updates and reload them

## Best Practices

1. **Use specific paths**: Prefer `Prefix` or `Exact` path types over `ImplementationSpecific`
2. **SSL everywhere**: Use `gateway.awesomeapi.com.br/ssl-redirect: "true"` for production applications
3. **Rate limiting**: Always configure appropriate rate limits for public APIs
4. **Health checks**: Enable health checks for better load balancing
5. **Circuit breakers**: Use circuit breakers for external service dependencies
6. **Compression**: Enable compression for static content and APIs
7. **CORS**: Configure CORS properly for web applications
8. **Authentication**: Use JWT or OAuth2 for API authentication
9. **Plugins**: Use plugins for cross-cutting concerns like logging and monitoring

## Troubleshooting

### Common Issues

1. **Annotation not working**: Check annotation key spelling and JSON format
2. **SSL redirect not working**: Ensure TLS is properly configured
3. **Rate limiting too aggressive**: Adjust burst limits for legitimate traffic spikes
4. **Backend connection failures**: Check backend protocol annotation
5. **CORS errors**: Verify allowed origins and methods
6. **Compression not working**: Check MIME types and minimum size settings

### Debugging

Use the gateway metrics endpoint `/metrics` to monitor:
- Request rates and response times
- Rate limiting statistics
- Circuit breaker states
- SSL certificate status
- Backend health check status

Check gateway logs for detailed error messages and configuration parsing issues.