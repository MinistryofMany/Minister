# notary-server

Runs the official [tlsn](https://github.com/tlsnotary/tlsn) notary binary. The notary co-signs TLS sessions that the Tessera browser extension generates during TLSNotary proof flows. Tessera itself does not talk to the notary — the extension does.

## Image

We use the `ghcr.io/tlsnotary/notary-server` image pinned to a specific tag (see `Dockerfile`). Re-pin only when validating against an updated `tlsn-verifier` crate version in `services/tlsn-verifier`.

## Config

The bundled `config.yaml` is a minimal dev config:
- Listens on `0.0.0.0:7047`.
- Generates a notary signing key on first boot and persists it to `/data/notary.key`. Mount `notary_data` to keep it across container restarts.
- TLS termination off (dev only). In prod the notary is reachable over TLS.

The notary's public key is what end-users (and any other RP that wants to cross-verify a presentation) need to validate signatures. Surface it via Tessera's existing `/.well-known/jwks.json` if we want a single discoverable place, or via a separate notary-specific endpoint.

## Pairing with the verifier

`services/tlsn-verifier` is what reads the finalized presentation server-side. The notary itself does not parse user-visible content — it only co-signs the TLS record stream. The split (notary online during the proof, verifier offline after) is per the TLSNotary protocol.
