# Multi-stage build for optimized production image
FROM rust:1.88-slim as builder

# Set debian frontend to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

# Build the application in release mode
RUN cargo build --release --package gateway-core --bin gateway

# Runtime stage
FROM debian:bookworm-slim

# Set debian frontend to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r gateway && useradd -r -g gateway gateway

# Create necessary directories
RUN mkdir -p /app/config /app/logs /app/data && \
    chown -R gateway:gateway /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/gateway /app/gateway

# Copy configuration files
COPY config/ /app/config/

# Set ownership
RUN chown -R gateway:gateway /app

# Switch to app user
USER gateway

# Set working directory
WORKDIR /app

# Expose ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Set environment variables
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1

# Run the application
CMD ["./gateway", "--config", "config/gateway.yaml"]