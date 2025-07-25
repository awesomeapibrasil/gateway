# Gateway - High-Performance API Gateway & Ingress Controller

Gateway is a high-performance API Gateway and Ingress Controller built with Rust, designed for cloud-native environments. It provides comprehensive Web Application Firewall (WAF) capabilities, distributed caching, and enterprise-grade features.

## 🚀 Features

### Core Features
- **High Performance**: Built with Rust for maximum performance and minimal resource usage
- **Web Application Firewall (WAF)**: Comprehensive L7 filtering with rate limiting
- **Distributed Caching**: Advanced caching system with compression and invalidation
- **Load Balancing**: Multiple algorithms with health checks and circuit breakers
- **Protocol Support**: HTTP/HTTPS/HTTP2/HTTP3, gRPC, WebSocket
- **Enterprise Security**: Authentication, authorization, and audit logging

### WAF Capabilities
- IP-based allow/block lists with CIDR support
- Header and User-Agent filtering
- URL pattern matching and malicious content detection
- Distributed rate limiting with multiple storage backends
- Complex rule engine similar to OPA
- Real-time rule updates without restarts

### Database Support
- **Serverless Databases**: Oracle Tables, DynamoDB, Firebase
- **Traditional Databases**: PostgreSQL, MySQL, MongoDB
- **Cloud Databases**: TiDB, MongoDB Atlas
- **Connection Pooling**: Automatic failover and load balancing

### Observability
- **Metrics**: Prometheus-compatible metrics
- **Logging**: Structured logging with multiple levels
- **Tracing**: OpenTelemetry integration
- **Health Checks**: Comprehensive health monitoring

### Deployment
- **Docker**: Optimized production-ready images
- **Kubernetes**: Helm charts for easy deployment
- **CI/CD**: GitHub Actions pipeline with automated testing
- **Cloud**: Support for GCP, AWS, Azure

## 📋 Requirements

- **Runtime**: Linux x86_64 or ARM64
- **Memory**: 512MB minimum, 1GB recommended
- **CPU**: 1 core minimum, 2+ cores recommended
- **Storage**: 1GB for logs and cache

### Optional Dependencies
- **Redis**: For distributed rate limiting and caching
- **Database**: PostgreSQL, MySQL, or MongoDB for persistence
- **Kubernetes**: 1.20+ for Helm deployment

## 🔧 Quick Start

### Docker
```bash
# Run with default configuration
docker run -p 8080:8080 -p 9090:9090 gcr.io/your-project/gateway:latest

# Run with custom configuration
docker run -p 8080:8080 -p 9090:9090 \
  -v $(pwd)/config:/app/config \
  gcr.io/your-project/gateway:latest
```

### Kubernetes with Helm
```bash
# Add the Helm repository
helm repo add gateway https://github.com/awesomeapibrasil/gateway/releases/download/helm-charts

# Install the chart
helm install gateway gateway/gateway

# Install with custom values
helm install gateway gateway/gateway -f values.yaml
```

### Binary Installation
```bash
# Download the latest release
curl -L https://github.com/awesomeapibrasil/gateway/releases/latest/download/gateway-linux-x86_64.tar.gz | tar xz

# Run the gateway
./gateway --config config/gateway.yaml
```

## ⚙️ Configuration

Gateway uses YAML configuration files. See the [Configuration Guide](docs/configuration/README.md) for detailed information.

### Basic Configuration
```yaml
server:
  bind_address: "0.0.0.0:8080"
  worker_threads: 4

waf:
  enabled: true
  rate_limiting:
    enabled: true
    requests_per_minute: 1000

upstream:
  backends:
    - name: "backend-1"
      address: "http://localhost:3000"
      weight: 1
```

### Environment Variables
- `GATEWAY_CONFIG`: Configuration file path (default: `config/gateway.yaml`)
- `RUST_LOG`: Log level (default: `info`)
- `DATABASE_URL`: Database connection string
- `JWT_SECRET`: JWT signing secret

## 🛡️ Security Features

### WAF Protection
- **SQL Injection**: Pattern-based detection and blocking
- **XSS**: Cross-site scripting prevention
- **CSRF**: Cross-site request forgery protection
- **Directory Traversal**: Path-based attack prevention
- **Rate Limiting**: Distributed rate limiting with burst protection

### Authentication & Authorization
- **JWT**: JSON Web Token support
- **OAuth2**: OAuth2 integration
- **LDAP**: LDAP authentication
- **RBAC**: Role-based access control

### Network Security
- **TLS**: TLS 1.2+ with configurable cipher suites
- **mTLS**: Mutual TLS for backend communication
- **IP Filtering**: CIDR-based IP allow/block lists
- **Network Policies**: Kubernetes network policy support

## 📊 Monitoring

### Metrics
Gateway exposes Prometheus-compatible metrics on `/metrics`:
- Request rate and latency
- Error rates and status codes
- WAF blocks and rate limits
- Backend health and response times
- Cache hit/miss rates

### Health Checks
- **Liveness**: `/health` endpoint
- **Readiness**: Component health status
- **Startup**: Initialization progress

### Logging
Structured JSON logging with configurable levels:
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "message": "Request processed",
  "request_id": "req-123",
  "method": "GET",
  "uri": "/api/users",
  "status": 200,
  "latency_ms": 45
}
```

## 🏗️ Architecture

Gateway is built with a modular architecture:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client        │────│   Gateway       │────│   Backend       │
│   Requests      │    │   (Rust/Pingora)│    │   Services      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                    ┌─────────┼─────────┐
                    │         │         │
            ┌───────▼──┐ ┌────▼───┐ ┌───▼────┐
            │   WAF    │ │ Cache  │ │  Auth  │
            │ Engine   │ │Manager │ │Manager │
            └──────────┘ └────────┘ └────────┘
```

### Components
- **Gateway Core**: Main proxy engine
- **WAF Engine**: Web Application Firewall
- **Cache Manager**: Distributed caching
- **Auth Manager**: Authentication and authorization
- **Database Manager**: Database abstraction layer
- **Monitoring Manager**: Metrics and observability
- **Plugin Manager**: Extensible plugin system

## 🔌 Plugin System

Gateway supports a flexible plugin system for extending functionality:

```rust
use gateway_plugins::{Plugin, PluginResult, RequestContext};

#[derive(Default)]
pub struct CustomPlugin;

impl Plugin for CustomPlugin {
    fn name(&self) -> &str {
        "custom-plugin"
    }

    async fn on_request(&self, ctx: &mut RequestContext) -> PluginResult {
        // Custom request processing logic
        Ok(())
    }
}
```

## 📚 Documentation

- [Installation Guide](docs/installation/README.md)
- [Configuration Reference](docs/configuration/README.md)
- [Deployment Guide](docs/deployment/README.md)
- [API Reference](docs/api/README.md)
- [Plugin Development](docs/plugins/README.md)
- [Troubleshooting](docs/troubleshooting/README.md)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone the repository
git clone https://github.com/awesomeapibrasil/gateway.git
cd gateway

# Build the project
cargo build

# Run tests
cargo test

# Run the gateway
cargo run -- --config config/gateway.yaml
```

### Testing
```bash
# Unit tests
cargo test --lib

# Integration tests
cargo test --test integration

# WAF tests
cargo test -p gateway-waf

# Performance benchmarks
cargo bench
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **GitHub Issues**: [Report bugs and feature requests](https://github.com/awesomeapibrasil/gateway/issues)
- **Discussions**: [Community discussions](https://github.com/awesomeapibrasil/gateway/discussions)
- **Documentation**: [Comprehensive guides and references](docs/)

## 🗺️ Roadmap

### v0.2.0
- [ ] Full Pingora integration
- [ ] Advanced WAF rules engine
- [ ] GraphQL support
- [ ] Service mesh integration

### v0.3.0
- [ ] AI-powered threat detection
- [ ] Advanced caching strategies
- [ ] Multi-cluster support
- [ ] Enhanced observability

### v1.0.0
- [ ] Production stability
- [ ] Enterprise features
- [ ] Certified cloud integrations
- [ ] Commercial support

## 🏆 Acknowledgments

- **Cloudflare**: For the Pingora framework
- **Rust Community**: For the amazing ecosystem
- **Contributors**: Everyone who helps improve the project

---

Built with ❤️ by the Gateway Team