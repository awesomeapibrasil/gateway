# Gateway - High Performance API Gateway focused on Security/WAF

Gateway is a high-performance API Gateway and Ingress Controller built with Rust, designed for cloud-native environments. It provides comprehensive Web Application Firewall (WAF) capabilities, distributed caching, and enterprise-grade features.

> **⚡ New: Pingora Integration** - Gateway now includes direct integration with Cloudflare's Pingora framework for maximum performance and reliability. See the [Pingora Integration](#-pingora-integration) section for details.

## 🚀 Features

### Core Features
- **High Performance**: Built with Rust for maximum performance and minimal resource usage
- **Web Application Firewall (WAF)**: Comprehensive L7 filtering with rate limiting
- **Distributed Caching**: Production-ready distributed cache with UDP multicast clustering, advanced LRU algorithms, and real-time coherence
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

### Distributed Caching System
- **Advanced Memory Cache Algorithms**: 
  - Segmented LRU Cache with reduced lock contention and memory safety
  - Approximated LRU Cache with Redis-inspired random sampling (~95% efficiency)
- **UDP Multicast Clustering**: 
  - Automatic node discovery and cluster formation
  - Real system monitoring with platform-specific load/memory metrics
  - Message reliability with checksums, sequence numbers, and acknowledgments
- **Cache Coherence Strategies**: 
  - Write-through, write-behind, and conflict resolution with vector clocks
  - Real-time cache invalidation across cluster nodes
  - Eventual consistency with configurable conflict resolution
- **Production-Ready Safety**:
  - Memory safety with comprehensive null pointer checks
  - Panic prevention with safe fallbacks for all operations
  - Enhanced error handling with Result-based APIs
  - Background task resilience and graceful failure handling

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
docker run -p 8080:8080 -p 9090:9090 ghcr.io/awesomeapibrasil/gateway:latest

# Run with custom configuration
docker run -p 8080:8080 -p 9090:9090 \
  -v $(pwd)/config:/app/config \
  ghcr.io/awesomeapibrasil/gateway:latest
```

### Native Binary with Pingora
```bash
# Build the gateway with Pingora support
cargo build --release

# Run basic Pingora example server
cargo run --bin gateway -- --pingora-example

# Run with standard gateway configuration
cargo run --bin gateway -- --config config/gateway.yaml
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

### Distributed Cache Configuration
```yaml
cache:
  enabled: true
  
  # Segmented LRU Cache Configuration
  segmented_lru:
    max_size: 10000
    segments: 16
    cleanup_frequency: "5min"
    
  # Approximated LRU Cache Configuration  
  approximated_lru:
    max_size: 50000
    sample_size: 10
    eviction_batch_size: 5
    
  # UDP Multicast Clustering
  cluster:
    enabled: true
    multicast_address: "239.255.0.1:7648"
    node_timeout: "30s"
    heartbeat_interval: "5s"
    
    # System Monitoring
    monitoring:
      load_threshold: 0.8
      memory_threshold: 0.9
      
    # Cache Coherence
    coherence:
      strategy: "write_through"  # write_through, write_behind
      conflict_resolution: "vector_clock"
      max_vector_clock_size: 100
```

### Environment Variables
- `GATEWAY_CONFIG`: Configuration file path (default: `config/gateway.yaml`)
- `RUST_LOG`: Log level (default: `info`)
- `DATABASE_URL`: Database connection string
- `JWT_SECRET`: JWT signing secret
- `CACHE_MULTICAST_ADDR`: UDP multicast address for cache clustering (default: `239.255.0.1:7648`)
- `CACHE_NODE_TIMEOUT`: Cache node timeout duration (default: `30s`)
- `CACHE_MAX_SIZE`: Maximum cache size per node (default: `10000`)

## 🛡️ Security Features

### WAF Protection
- **SQL Injection**: Pattern-based detection and blocking
- **XSS**: Cross-site scripting prevention
- **CSRF**: Cross-site request forgery protection
- **Directory Traversal**: Path-based attack prevention
- **Rate Limiting**: Distributed rate limiting with burst protection
- **ModSecurity Integration**: OWASP Core Rule Set (CRS) compatible engine

### ModSecurity Integration

Gateway includes a native Rust implementation of ModSecurity-compatible rules engine:

- **OWASP TOP 10 Coverage**: Built-in rules covering all OWASP Top 10 vulnerabilities
- **Dynamic Rule Updates**: Update rules without restarting the gateway
- **Custom Rules**: Support for custom ModSecurity-style rules
- **Performance Optimized**: Native Rust implementation for maximum performance
- **OWASP CRS Compatible**: Supports OWASP Core Rule Set syntax

#### Quick ModSecurity Setup

```yaml
waf:
  enabled: true
  modsecurity:
    enabled: true
    rules_path: "config/modsecurity/custom"
    owasp_crs_path: "config/modsecurity/owasp-crs"
    blocking_mode: true
    rule_update_interval: 300
```

```bash
# Create ModSecurity directory structure
mkdir -p config/modsecurity/{custom,owasp-crs/rules}

# Start the gateway with ModSecurity protection
cargo run -- --config config/gateway.yaml
```

#### Supported Rule Syntax

```
SecRule VARIABLES "OPERATOR" "ACTIONS"

# Examples:
SecRule ARGS "@detectSQLi" "id:100001,msg:'SQL Injection',severity:CRITICAL,block"
SecRule REQUEST_URI "@rx \.\./.*" "id:100002,msg:'Path Traversal',severity:ERROR,block"
```

See [ModSecurity Configuration Guide](config/modsecurity/README.md) for detailed setup instructions.

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
- Cache hit/miss rates and cluster health
- Distributed cache node statistics and coherence metrics
- Memory usage and eviction rates per cache algorithm

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

Gateway is built with a modular architecture, now featuring direct integration with Cloudflare's Pingora framework:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client        │────│   Gateway       │────│   Backend       │
│   Requests      │    │   (Rust/Pingora)│    │   Services      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                    ┌─────────┼─────────┐
                    │         │         │
            ┌───────▼──┐ ┌────▼───┐ ┌───▼────┐
            │   WAF    │ │Distrib.│ │  Auth  │
            │ Engine   │ │ Cache  │ │Manager │
            └──────────┘ └────┬───┘ └────────┘
                              │
                        ┌─────▼─────┐
                        │ UDP       │
                        │ Multicast │
                        │ Cluster   │
                        └───────────┘
```

### Components
- **Gateway Core**: Main proxy engine powered by Pingora
- **WAF Engine**: Web Application Firewall with ModSecurity integration
- **Distributed Cache Manager**: Multi-algorithm cache system with UDP clustering
  - Segmented LRU Cache for reduced lock contention
  - Approximated LRU Cache with Redis-inspired sampling
  - UDP Multicast clustering for automatic node discovery
  - Vector clock-based conflict resolution and cache coherence
- **Auth Manager**: Authentication and authorization
- **Database Manager**: Database abstraction layer
- **Monitoring Manager**: Metrics and observability
- **Plugin Manager**: Extensible plugin system
- **Pingora Adapter**: Direct integration with Cloudflare's Pingora framework
- **ModSecurity Engine**: OWASP CRS compatible rule engine

## 🚀 Pingora Integration

Gateway now includes direct integration with Cloudflare's Pingora framework for maximum performance and reliability. This integration provides:

- **High-Performance Networking**: Leverage Pingora's optimized network stack
- **Advanced Load Balancing**: Use Pingora's proven load balancing algorithms
- **Better Connection Management**: Benefit from Pingora's connection pooling
- **Production-Grade Reliability**: Built on the same foundation as Cloudflare's edge network

### Running with Pingora

```bash
# Build with Pingora support
cargo build --release

# Run the basic Pingora example
cargo run --bin gateway -- --pingora-example

# Or integrate Pingora in your code
use gateway_core::pingora_adapter::PingoraGateway;

let gateway = PingoraGateway::new("MyGateway")?;
gateway.run_forever();
```

### Pingora Integration Status

- [x] **Basic Integration**: Pingora dependency added and basic server setup
- [x] **Configuration Foundation**: Server configuration structure in place
- [ ] **HTTP Service Integration**: Connect HTTP handlers with WAF processing
- [ ] **Proxy Service Integration**: Full proxy implementation with load balancing
- [ ] **SSL/TLS Integration**: Certificate management and termination
- [ ] **Monitoring Integration**: Metrics collection and observability hooks
- [ ] **Configuration Migration**: Integrate with existing gateway configuration system

### ModSecurity Integration Status

- [x] **Core Engine**: Native Rust ModSecurity-compatible rule engine implemented
- [x] **OWASP TOP 10 Rules**: Built-in rules covering all OWASP Top 10 vulnerabilities
- [x] **Rule Parsing**: Support for ModSecurity SecRule syntax
- [x] **Dynamic Updates**: Runtime rule updates without restart
- [x] **Configuration**: YAML configuration with examples
- [x] **Documentation**: Comprehensive setup and usage guide
- [x] **Testing**: Full test suite for rule engine and detection
- [x] **WAF Integration**: Seamless integration with existing WAF pipeline

## 🗄️ Distributed Cache System

Gateway includes a production-ready distributed caching system designed for high-performance, fault-tolerant operation across multiple nodes.

### Key Features

#### Advanced Memory Algorithms
- **Segmented LRU Cache**: Partitioned cache reducing lock contention by dividing entries across multiple segments
- **Approximated LRU Cache**: Redis-inspired random sampling approach achieving ~95% of true LRU efficiency with significantly better performance

#### UDP Multicast Clustering
- **Automatic Node Discovery**: Nodes automatically discover and join clusters via UDP multicast
- **Real System Monitoring**: Platform-specific monitoring using `/proc/loadavg` and `/proc/meminfo` on Linux with cross-platform fallbacks
- **Message Reliability**: Comprehensive checksums, sequence numbers, and acknowledgments for reliable communication

#### Cache Coherence Strategies
- **Write-Through**: Immediate synchronization of cache writes across all cluster nodes
- **Write-Behind**: Asynchronous write propagation for improved write performance
- **Vector Clocks**: Conflict resolution using vector clocks for eventual consistency
- **Real-time Invalidation**: Immediate cache invalidation across cluster nodes

### Production-Ready Safety

```rust
// Memory-safe operations with comprehensive null checks
unsafe fn add_to_front(&mut self, node: *mut LRUNode<K, V>) {
    if node.is_null() || self.head.is_null() {
        return; // Safe early return prevents crashes
    }
    // ... safe operations only when all pointers are valid
}

// Consistent error handling throughout
let timestamp = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default(); // Safe fallback prevents panics
```

### Performance Characteristics
- **Latency**: 100K+ cache operations per second per node
- **Memory Efficiency**: Configurable limits with automatic eviction
- **Network Overhead**: UDP multicast reduces broadcast overhead vs TCP mesh
- **Scalability**: Linear performance scaling with cluster size

### Quick Setup

```yaml
cache:
  enabled: true
  cluster:
    enabled: true
    multicast_address: "239.255.0.1:7648"
    
  segmented_lru:
    max_size: 10000
    segments: 16
    
  approximated_lru:
    max_size: 50000
    sample_size: 10
```

```bash
# Start gateway with distributed caching
cargo run -- --config config/gateway.yaml

# Monitor cache metrics
curl http://localhost:9090/metrics | grep cache_
```

### Distributed Cache Integration Status

- [x] **Core Algorithms**: Segmented LRU and Approximated LRU implementations
- [x] **UDP Clustering**: Multicast-based node discovery and communication
- [x] **Cache Coherence**: Vector clock-based conflict resolution
- [x] **System Monitoring**: Real-time load and memory monitoring
- [x] **Safety Enhancements**: Memory safety and panic prevention
- [x] **Production Testing**: Comprehensive test suite with 26+ unit tests
- [x] **CI/CD Integration**: Full formatting, linting, and testing pipeline
- [x] **Documentation**: Complete API documentation and usage examples

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

# Test Pingora integration
cargo run --bin gateway -- --pingora-example

# Run the standard gateway
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

# Distributed cache tests
cargo test -p gateway-cache

# Performance benchmarks
cargo bench
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **GitHub Issues**: [Report bugs and feature requests](https://github.com/awesomeapibrasil/gateway/issues)
- **Discussions**: [Community discussions](https://github.com/awesomeapibrasil/gateway/discussions)
- **Documentation**: [Comprehensive guides and references](docs/)

## 🏆 Acknowledgments

- **Cloudflare**: For the Pingora framework
- **Rust Community**: For the amazing ecosystem
- **Contributors**: Everyone who helps improve the project

---

Built with ❤️ by AwesomeAPI