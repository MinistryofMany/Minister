# Two-stage Rust build. Cargo's dependency graph is layered so a
# source-only change doesn't bust the deps cache.
FROM rust:1.83-slim AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache deps. Touch a dummy main.rs so cargo can build without source.
COPY Cargo.toml ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src target/release/deps/tessera_tlsn_verifier*

# Real build.
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/tessera-tlsn-verifier /usr/local/bin/tessera-tlsn-verifier

EXPOSE 7048
ENV VERIFIER_MODE=passthrough
ENV RUST_LOG=info
CMD ["tessera-tlsn-verifier"]
