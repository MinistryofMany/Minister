# Pin the official tlsn notary-server image (never built from source here).
# Re-pin only in lockstep with the tlsn-core tag in services/tlsn-verifier
# and the tlsn-js version in apps/extension — the attestation/presentation
# formats must match across all three.
FROM ghcr.io/tlsnotary/notary-server:v0.1.0-alpha.11

# The image already exposes 7047 and runs the notary binary as its
# entrypoint. Mount a `config.yaml` into /app/config/config.yaml to
# override the bundled defaults.
EXPOSE 7047
