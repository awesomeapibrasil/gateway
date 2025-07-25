# Installation Guide

This guide covers different methods to install and run the Gateway.

## Prerequisites

### System Requirements
- **Operating System**: Linux (x86_64 or ARM64), macOS, Windows
- **Memory**: 512MB minimum, 1GB recommended
- **CPU**: 1 core minimum, 2+ cores recommended
- **Storage**: 1GB for logs and cache
- **Network**: Ports 8080 (HTTP) and 9090 (Metrics) available

### Optional Dependencies
- **Redis**: For distributed rate limiting and caching
- **Database**: PostgreSQL, MySQL, or MongoDB for persistence
- **Kubernetes**: 1.20+ for Helm deployment

## Installation Methods

### 1. Docker (Recommended)

#### Quick Start
```bash
docker run -d \
  --name gateway \
  -p 8080:8080 \
  -p 9090:9090 \
  gcr.io/your-project/gateway:latest
```

#### With Custom Configuration
```bash
# Create config directory
mkdir -p config

# Copy example configuration
curl -o config/gateway.yaml https://raw.githubusercontent.com/awesomeapibrasil/gateway/main/config/gateway.yaml

# Run with mounted config
docker run -d \
  --name gateway \
  -p 8080:8080 \
  -p 9090:9090 \
  -v $(pwd)/config:/app/config \
  gcr.io/your-project/gateway:latest
```

#### Docker Compose
```yaml
version: '3.8'
services:
  gateway:
    image: gcr.io/your-project/gateway:latest
    ports:
      - "8080:8080"
      - "9090:9090"
    volumes:
      - ./config:/app/config
      - gateway-data:/app/data
    environment:
      - RUST_LOG=info
    restart: unless-stopped
    
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

volumes:
  gateway-data:
  redis-data:
```

### 2. Kubernetes with Helm

#### Add Helm Repository
```bash
helm repo add gateway https://awesomeapibrasil.github.io/gateway/helm
helm repo update
```

#### Install with Default Values
```bash
helm install gateway gateway/gateway
```

#### Install with Custom Values
```bash
# Create custom values file
cat > values.yaml << EOF
replicaCount: 3

config:
  waf:
    enabled: true
    rate_limiting:
      requests_per_minute: 2000
  
  upstream:
    backends:
      - name: "api-v1"
        address: "http://api-service:3000"
        weight: 1
EOF

helm install gateway gateway/gateway -f values.yaml
```

#### Upgrade
```bash
helm upgrade gateway gateway/gateway -f values.yaml
```

### 3. Binary Installation

#### Download Latest Release
```bash
# Linux x86_64
curl -L https://github.com/awesomeapibrasil/gateway/releases/latest/download/gateway-linux-x86_64.tar.gz | tar xz

# Linux ARM64
curl -L https://github.com/awesomeapibrasil/gateway/releases/latest/download/gateway-linux-arm64.tar.gz | tar xz

# macOS
curl -L https://github.com/awesomeapibrasil/gateway/releases/latest/download/gateway-darwin-x86_64.tar.gz | tar xz
```

#### Install System-wide
```bash
sudo cp gateway /usr/local/bin/
sudo chmod +x /usr/local/bin/gateway
```

#### Create Configuration
```bash
sudo mkdir -p /etc/gateway
sudo curl -o /etc/gateway/gateway.yaml https://raw.githubusercontent.com/awesomeapibrasil/gateway/main/config/gateway.yaml
```

#### Create Systemd Service
```bash
sudo tee /etc/systemd/system/gateway.service << EOF
[Unit]
Description=Gateway API Gateway
After=network.target

[Service]
Type=simple
User=gateway
Group=gateway
ExecStart=/usr/local/bin/gateway --config /etc/gateway/gateway.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create user
sudo useradd -r -s /bin/false gateway

# Enable and start service
sudo systemctl enable gateway
sudo systemctl start gateway
```

### 4. Build from Source

#### Prerequisites
- Rust 1.70+
- Git

#### Clone and Build
```bash
git clone https://github.com/awesomeapibrasil/gateway.git
cd gateway

# Build in release mode
cargo build --release

# The binary will be in target/release/gateway
```

#### Install
```bash
sudo cp target/release/gateway /usr/local/bin/
```

## Configuration

### Environment Variables
Set these environment variables for basic configuration:

```bash
# Configuration file path
export GATEWAY_CONFIG="/path/to/gateway.yaml"

# Log level
export RUST_LOG=info

# Database URL (if using database)
export DATABASE_URL="postgresql://user:password@localhost:5432/gateway"

# JWT secret (if using authentication)
export JWT_SECRET="your-secret-key"
```

### Basic Configuration File
Create a basic configuration file:

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

monitoring:
  enabled: true
  metrics_port: 9090
```

## Verification

### Check Installation
```bash
# Check version
gateway --version

# Test configuration
gateway --config config/gateway.yaml --dry-run
```

### Health Check
```bash
# Check if gateway is running
curl http://localhost:8080/health

# Check metrics
curl http://localhost:9090/metrics
```

### Logs
```bash
# Docker logs
docker logs gateway

# Systemd logs
sudo journalctl -u gateway -f

# Direct binary logs (if running in foreground)
gateway --config config/gateway.yaml
```

## Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Check what's using the port
sudo netstat -tlnp | grep :8080

# Kill the process or use a different port
```

#### Permission Denied
```bash
# Ensure proper permissions
sudo chown -R gateway:gateway /etc/gateway
sudo chmod 644 /etc/gateway/gateway.yaml
```

#### Configuration Errors
```bash
# Validate configuration
gateway --config config/gateway.yaml --validate

# Check logs for specific errors
gateway --config config/gateway.yaml --debug
```

#### Memory Issues
```bash
# Check memory usage
docker stats gateway

# Adjust memory limits in configuration
server:
  max_connections: 5000  # Reduce if memory is limited
```

### Getting Help

1. Check the [troubleshooting guide](../troubleshooting/README.md)
2. Review logs for error messages
3. Open an issue on [GitHub](https://github.com/awesomeapibrasil/gateway/issues)
4. Join our [community discussions](https://github.com/awesomeapibrasil/gateway/discussions)

## Next Steps

- [Configure the Gateway](../configuration/README.md)
- [Deploy to Production](../deployment/README.md)
- [Set up Monitoring](../monitoring/README.md)
- [Configure WAF Rules](../waf/README.md)