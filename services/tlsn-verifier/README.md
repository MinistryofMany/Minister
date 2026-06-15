# tlsn-verifier

Rust HTTP sidecar. Verifies TLSNotary presentations produced by the Minister browser extension and returns the verified transcript to the Minister Next.js app over HTTP.

## API

`POST /verify`

```json
{
  "presentation": "<base64>",
  "expectedDomain": "id.me"
}
```

On success (HTTP 200):

```json
{
  "ok": true,
  "transcript": { "sent": "...", "received": "...", "serverName": "id.me" },
  "notaryKey": "<base64 ed25519 public key, optional>"
}
```

On verification failure (also HTTP 200 — protocol-level error rather than HTTP-level):

```json
{ "ok": false, "error": "server name mismatch" }
```

`GET /health` returns `200 ok`.

## Modes

`VERIFIER_MODE` (env, default `passthrough`):

- `passthrough` — the "presentation" is base64-encoded JSON of shape `{ sent, received, serverName }`. We trust it and only enforce that the server name matches `expectedDomain`. Lets Minister plugin flows be exercised end-to-end without a TLSNotary prover in the loop. **Dev only.**
- `real` — uses the `tlsn-verifier` crate to cryptographically verify the presentation against the notary signature. Not yet wired (see `verify_real()` in `src/main.rs`). Pin the crate in `Cargo.toml`, then replace the function body.

## Why a Rust sidecar over WASM-in-Node

- Pins one `tlsn-verifier` crate version, isolated from the Next.js dep graph.
- Keeps all `tlsn-*` code in Rust (where it lives upstream), so upstream breaking changes don't ripple through the Node app.
- One small HTTP hop per submission, called only from the wizard runtime on the server side.

## Run locally

Inside docker-compose: the `tlsn-verifier` service is enabled and exposes `:7048`. Minister reads `TLSN_VERIFIER_URL` (defaults to `http://tlsn-verifier:7048` for in-network calls).

Standalone:

```
cd services/tlsn-verifier
cargo run
```

## Tests

`cargo test` covers the passthrough path + host-matching helpers. Real-mode tests land with the crate wiring.
