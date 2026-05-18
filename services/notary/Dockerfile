# Pin the official tlsn notary-server image. Re-pin only when
# validating against an updated tlsn-verifier crate version in
# services/tlsn-verifier.
FROM ghcr.io/tlsnotary/notary-server:v0.1.0-alpha.11

# The image already exposes 7047 and runs the notary binary as its
# entrypoint. Mount a `config.yaml` into /app/config/config.yaml to
# override the bundled defaults.
EXPOSE 7047
