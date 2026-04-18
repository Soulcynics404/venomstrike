# Multi-stage build for VenomStrike
FROM rust:1.75-slim as builder

WORKDIR /usr/src/venomstrike

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# Build actual project
COPY . .
RUN cargo build --release

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    nmap \
    wkhtmltopdf \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/venomstrike

COPY --from=builder /usr/src/venomstrike/target/release/venomstrike /usr/local/bin/venomstrike
COPY payloads/ ./payloads/
COPY config/ ./config/
COPY data/ ./data/

RUN mkdir -p /opt/venomstrike/reports

ENTRYPOINT ["venomstrike"]
CMD ["--help"]