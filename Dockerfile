# Build stage
FROM rust:1.100-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY static ./static

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    tcpdump \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/honeypot /app/honeypot

# Copy static files and config
COPY static ./static
COPY config.toml ./config.toml

# Create data directory for GeoIP database
RUN mkdir -p data

# Expose ports (HTTP + commonly attacked TCP & passive UDP ports)
EXPOSE 80 443
EXPOSE 21-23 25 53 110-111 135 139 143 445
EXPOSE 1433 1521 2323 2375 3306 3389 5432 5900 6379 8080 9200 11434 27017
EXPOSE 53/udp 123/udp 161/udp 1900/udp 5060/udp 11211/udp

# Run with necessary capabilities
# Note: Container must be run with --cap-add=NET_BIND_SERVICE for low ports
# And --cap-add=NET_RAW for ICMP capture
CMD ["./honeypot"]
