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
- `real` — cryptographically verifies the presentation via `tlsn-core` (`Presentation::verify`), pinned to the same tag as the notary image (`v0.1.0-alpha.11`). See `src/tlsn.rs`.

### Real mode

The extension submits `base64(bincode(tlsn_core::presentation::Presentation))`. `verify_real` decodes it, then `Presentation::verify(&CryptoProvider::default())` checks:

1. the **notary signature** over the attestation,
2. the **server identity proof** — the server's certificate chain, validated against the webpki roots baked into `tlsn-core` at the recorded connection time, binding the session to a server name, and
3. the **transcript proof** — that the revealed bytes are authentic to that attested session.

Bytes the prover chose not to reveal are marked with `X` (`set_unauthed`) so a plugin's substring check can't be satisfied by unauthenticated data. We then enforce `serverName == expectedDomain` and return the revealed `{ sent, received, serverName }` plus the notary key (hex) in `notaryKey`.

**Why `tlsn-core`, not the `tlsn-verifier` crate:** `tlsn-verifier` implements the _interactive_ MPC-verifier role (the verifier IS the notary, and there is no separate presentation to submit later). Minister runs the offline notary + presentation model — a notary co-signs, and the browser submits a `Presentation` after the fact — so `tlsn_core::presentation::Presentation::verify` is the correct entry point.

**Notary pinning (`TLSN_NOTARY_PUBLIC_KEY`).** `verify()` proves a presentation is internally consistent and signed by _some_ notary; it does not decide the notary is ours. Set `TLSN_NOTARY_PUBLIC_KEY` to our notary's verifying key (hex, optional `0x`) to fail closed on any other notary. Read our notary's key from `GET http://notary-server:7047/info` (or the tlsn-js `NotaryServer.publicKey('hex')`). When unset, the sidecar still enforces cryptographic validity but logs a warning that it is not pinning the notary — do not run production unpinned.

**Fail-closed guarantee:** `verify_real` returns `Err` for every input it cannot cryptographically verify (bad base64, non-presentation bytes, failed signature/cert/transcript check, server-name mismatch, missing identity/transcript proof, or notary-key mismatch). It never fabricates a success. A test fixture built from a **real** presentation still needs a live prove run against a notary (tlsn-core's `Secrets` are `pub(crate)`, so a full presentation cannot be synthesized from the public API); the committed tests cover the fail-closed paths.

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

`cargo test` covers the passthrough path, host-matching helpers, and the real-mode **fail-closed** paths (bad base64, valid base64 that is not a presentation, empty/truncated bincode) plus the notary-key normalization/compare helpers. A real-presentation happy-path fixture is deferred — it requires a live prove session (see the fail-closed note under "Real mode").

Build note: `real` mode pulls `tlsn-core` from git (tag `v0.1.0-alpha.11`); the first `cargo build` fetches and compiles it. `Cargo.lock` pins the exact rev.
