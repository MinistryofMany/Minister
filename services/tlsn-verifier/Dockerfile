# Two-stage Rust build. Cargo's dependency graph is layered so a
# source-only change doesn't bust the deps cache.
FROM rust:1.90-slim AS builder

WORKDIR /build
# git + ca-certificates: tlsn-core is a git dependency, so cargo must fetch
# from github over TLS. pkg-config/libssl for any transitive openssl-sys.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Cache deps. Copy the manifest AND lockfile so the pinned git revs resolve
# identically, then touch a dummy main.rs so cargo can build deps without the
# real source. `mod tlsn;` in the real main.rs is not present here, which is
# fine: this layer only warms the dependency cache.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src target/release/deps/minister_tlsn_verifier*

# Real build.
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/minister-tlsn-verifier /usr/local/bin/minister-tlsn-verifier

EXPOSE 7048
# No VERIFIER_MODE default: the binary defaults to `real` (fails closed, and
# refuses to boot without TLSN_NOTARY_PUBLIC_KEY). Passthrough is a deliberate,
# loud opt-in only (VERIFIER_MODE=passthrough + ALLOW_INSECURE_PASSTHROUGH=1, or
# TLSN_DEV=1) — never baked into the image.
ENV RUST_LOG=info
CMD ["minister-tlsn-verifier"]
