# TLSNotary pivot: proxy mode, interactive verification, signed attestations

Implementation plan (decided 2026-07-13). Review before teardown. No code in this
commit; branch `docs/tlsn-proxy-mode-plan` carries only this doc.

## The decision

Replace the offline notary + submitted-Presentation model (Stage 6 as built so far)
with TLSNotary **proxy mode** on **v0.1.0-alpha.15** and the **interactive
verification** model, where the verifier is Ministry's own:

- The extension prover speaks WebSocket straight to a Ministry-run verifier. In
  proxy mode the verifier does the TCP leg to the target server itself, so the
  separate WS->TCP relay is dead. Delete `services/ws-proxy`, do not port it.
- The offline notary is dead upstream (notary-server/notary-client removed in
  alpha.13) and dead here. Delete `services/notary`. Do not build on
  `tlsn_core::Presentation::verify`.
- The verifier runs as its own isolated container with its own Ed25519 signing
  key. After a successful interactive proof it signs an attestation over the
  disclosed facts; the extension carries that attestation to Minister; Minister
  verifies the signature against a pinned public key and issues the badge VC.

## Upstream facts verified (2026-07-13)

Checked against github.com/tlsnotary/tlsn releases and source at tag
`v0.1.0-alpha.15`, plus the maintained consumer repo github.com/tlsnotary/tlsn-extension:

- Releases: alpha.13 (2025-10-15) merged the prover and verifier crates into a
  single `tlsn` crate, split attestation into `tlsn-attestation`, and removed
  notary-server/notary-client. alpha.14 (2026-01-14) added the `Session<Io>`
  type. alpha.15 (2026-05-21) added the proxy-TLS commit protocol ("the verifier
  sits between the prover and the server and just forwards the encrypted TLS
  traffic") and reorganized the WASM SDK around `tlsn-sdk-core` with `tlsn-wasm`
  as a thin wasm_bindgen layer taking an injected `IoChannel` from JS. Rust 1.95,
  edition 2024.
- Crates at the tag (`crates/`): `tlsn`, `attestation`, `core`, `sdk-core`,
  `wasm`, `formats`, plus fixtures/examples. Nothing usable is on crates.io for
  our purposes; the reference consumer pins by git tag.
- Proxy-mode Rust API, from `crates/examples/proxy/proxy.rs` at the tag:
  prover side `Session::new(io)` -> `handle.new_prover(ProverConfig)` ->
  `.commit(ProxyTlsConfig::builder().server_name(...).build())` ->
  `prover.connect(TlsClientConfig)` -> HTTP over the returned TLS stream ->
  `ProveConfig::builder(transcript)` with `.server_identity()` /
  `.reveal_sent()` / `.reveal_recv()` -> `prover.prove()`. Verifier side
  `handle.new_verifier(VerifierConfig)` -> `verifier.commit()` returns
  `VerifierCommitStart::{Mpc,Proxy}`; the Proxy arm gets the target from
  `verifier.config().server_name()`, opens the TCP socket itself, and passes it
  to `.accept().await?.run(socket)`. Then `.verify()` -> inspect
  `verifier.request().server_identity()` -> `.accept()` yields
  `VerifierOutput { server_name, transcript, transcript_commitments }`.
- Browser SDK: npm `tlsn-js` is deprecated ("Check the tlsn-extension repository
  instead") and its repo was archived 2026-02-04; last publish alpha.12. npm
  `tlsn-wasm` latest is **0.1.0-alpha.15**, and tlsn-extension's MV3 extension
  pins exactly `tlsn-wasm: 0.1.0-alpha.15`. Its JS call sequence
  (`packages/extension/src/offscreen/ProveManager/worker.ts`):
  `initialize(loggingConfig, hardwareConcurrency)` (fallback
  `initialize(null, 1)`), `new Prover(config)` with
  `{ server_name, mode: "Proxy" | "Mpc", max_sent_data, max_recv_data, network }`,
  `prover.setup(ioChannel)`, `prover.send_request(serverIo, request)` where
  serverIo **must be null in proxy mode** (traffic rides the session mux),
  `prover.transcript()`, `prover.reveal(reveal, commit|null)`. The `IoChannel`
  interface is `{ read(): Promise<Uint8Array|null>, write(Uint8Array):
Promise<void>, close(): Promise<void> }`; a WebSocket adapter lives at
  `packages/common/src/io-channel.ts` (`@tlsn/common`, not published to npm, so
  we write our own ~80-line equivalent).
- Reference verifier server: `tlsn-extension/servers/verifier` pins
  `tlsn = { git = "https://github.com/tlsnotary/tlsn.git", tag = "v0.1.0-alpha.15",
features = ["mozilla-certs"] }`, axum 0.8 + `ws_stream_tungstenite` 0.15 +
  `async-tungstenite` 0.29. Two WS endpoints: a JSON control channel (`/session`:
  register -> sessionId -> completion message) and the raw tlsn session mux
  (`/verifier?sessionId=...`). Its Proxy arm dials `server_name:443` with **no
  allowlist** - ours must add one.
- docs.tlsnotary.org is currently serving an unbound-endpoint error page; all
  verification above is from the release notes and pinned source.

## Held branch: feat/tlsn-proof-path (do not merge)

Three commits ahead of main, all built against alpha.11, all obsoleted in whole
or part by this pivot:

- `a22857e` ws-proxy: real Go WS->TCP relay with allowlist + rate limits
  (~900 lines + tests). **Discard entirely** - proxy mode removes the component.
  Its allowlist/limits concerns move into the new verifier (below).
- `e2b0aa3` tlsn-verifier: `Presentation::verify` via `tlsn-core` alpha.11 +
  notary key pinning. **Discard the tlsn path** (offline model). The axum
  scaffolding, mode plumbing, and fail-closed posture inform the rewrite but the
  service is rebuilt around a WS session, not an HTTP `/verify`.
- `0466e30` extension: tlsn-js alpha.11 prover in an offscreen document.
  **Salvage the scaffolding**: `build.mjs` (esbuild + wasm asset copy),
  offscreen-document pattern, `messages.ts`, manifest COOP/COEP + offscreen
  permission, `config.ts` shape. Replace every tlsn-js call with tlsn-wasm
  alpha.15; `encoding.ts` (hex->base64) is no longer needed.

Practical handling: cherry-pick `0466e30` onto the work branch as the extension
starting point, then retarget; take nothing from the other two. Delete the
branch once the new path is green.

## 1. Delete

- `services/notary/` - entire directory (Dockerfile pinning
  `ghcr.io/tlsnotary/notary-server:v0.1.0-alpha.11`, README).
- `services/ws-proxy/` - entire directory (stub on main; Go impl only on the
  held branch, which is not merged).
- `docker-compose.yml`: the `notary-server` service, the `notary_data` volume,
  the ws-proxy comment block, and the app's `TLSN_VERIFIER_URL` env.
- `apps/minister/src/lib/tlsn-verifier.ts` + `tlsn-verifier.test.ts` (HTTP
  sidecar client, `validateTlsnVerifierConfig`, the
  `MINISTER_TLSN_VERIFIER_ALLOWED_HOSTS` SSRF-allowlist machinery - all moot:
  Minister no longer makes any server-side call to the verifier).
- `apps/minister/src/instrumentation.ts`: the `validateTlsnVerifierConfig()`
  call and import.
- `apps/minister/.env.example`: `TLSN_VERIFIER_URL` entry (keep
  `TLSN_SUBMIT_ALLOWED_ORIGINS`).
- `services/tlsn-verifier/src/main.rs` passthrough mode and the `/verify` HTTP
  wire (whole file is rewritten; the service name and port stay).
- Docs: rewrite the "TLSNotary integration (Stage 6+)" section of `CLAUDE.md`,
  the Stage 6 line in the stage plan, `services/*/README.md`, and the tlsn
  bullets in `docs/status.md`.

## 2. Create: the interactive verifier service

Rewrite `services/tlsn-verifier` in place (Rust, same directory, same :7048).

**Dependencies** (mirror the reference server, add signing):

```toml
tlsn = { git = "https://github.com/tlsnotary/tlsn.git", tag = "v0.1.0-alpha.15", features = ["mozilla-certs"] }
axum = "0.8"                      # WS upgrade + health/info routes
ws_stream_tungstenite = "0.15"    # WS -> AsyncRead/AsyncWrite for Session::new
async-tungstenite = { version = "0.29", features = ["tokio-runtime"] }
ed25519-dalek = "2"               # attestation signing
tokio, tokio-util (compat), serde, serde_json, base64, tracing, eyre/anyhow
```

Commit `Cargo.lock`. Dockerfile: bump `rust:1.83-slim` -> `rust:1.95-slim`
(alpha.15 is edition 2024); keep the two-stage layout and deps-caching layer.

**Endpoints**

- `GET /health` - liveness.
- `GET /info` - `{ publicKey: <b64 raw 32B Ed25519>, version, tlsnVersion:
"0.1.0-alpha.15" }`. Operational convenience for pinning; Minister does NOT
  fetch it at runtime (pin via env, below).
- `WS /session` - JSON control channel. Client sends
  `{ type: "register", maxSentData, maxRecvData, nonce }`; server stores the
  pending session, replies `{ type: "session_registered", sessionId }`; on
  completion sends `{ type: "session_completed", attestation }` or
  `{ type: "error", message }` and closes.
- `WS /verifier?sessionId=<id>` - the raw tlsn session mux. Adapted via
  `WsStream` -> `Session::new(socket.compat())`, then the alpha.15 verifier
  flow. **Reject `VerifierCommitStart::Mpc`** - proxy-only, one arm, no MPC
  compute budget on this box.

**Proxy arm hardening** (this is where the dead ws-proxy's controls land):

- Target allowlist: `TLSN_ALLOWED_TARGETS` (comma-separated exact hostnames).
  `server_name` not in the list -> reject before any TCP dial. Empty/unset ->
  reject everything (fail closed). Dev compose sets `example.com`. Target port
  fixed at 443.
- Enforce `maxSentData`/`maxRecvData` against env caps (`TLSN_MAX_SENT_DATA`,
  `TLSN_MAX_RECV_DATA`, defaults 4KiB/16KiB) before accepting the commit.
- Global concurrent-session semaphore (`TLSN_MAX_SESSIONS`, default 4) and a
  per-session wall-clock timeout (60s). No per-IP limiter in v1; the semaphore
  bounds abuse and Minister's badge issuance is the thing of value anyway.
  <!-- ponytail: global semaphore; per-IP buckets if the verifier is ever abused as a proxy -->

**Verification requirements** (all fail closed): prover revealed
`server_identity` and transcript data; `server_name` in the allowlist. The
verifier does not know plugin semantics (needle etc.) - that stays in Minister.

**Attestation** - the seam Minister trusts:

```jsonc
// payload = exact serde_json bytes, transmitted base64; signature = Ed25519 over those bytes
{
  "v": 1,
  "tlsnVersion": "0.1.0-alpha.15",
  "time": 1760000000, // unix seconds at verification
  "nonce": "<echoed from register>",
  "serverName": "example.com", // from VerifierOutput, DNS-validated by tlsn
  "sent": "<b64 of transcript.sent_unsafe()>", // \0 bytes = redacted
  "recv": "<b64 of transcript.received_unsafe()>",
}
```

Wire shape: `attestation: { payload: <b64(json-bytes)>, signature: <b64(64B)> }`.
Sign-then-wrap over the exact byte string sidesteps JSON canonicalization
entirely; Minister verifies the signature first, then parses the bytes.

**Key handling**

- `TLSN_ATTESTATION_KEY` env: base64 32-byte Ed25519 seed. Required; the
  service refuses to boot without it (no silent ephemeral keys - a restart
  would invalidate Minister's pin).
- `minister-tlsn-verifier --gen-key` subcommand prints a fresh
  `{seed_b64, publicKey_b64}` pair and exits; used once for dev and once for
  prod provisioning.
- Dev compose: a clearly-marked dev-only seed as the compose default (same
  pattern as `DEMO_CLIENT_SECRET`), pubkey wired into the app's
  `TLSN_VERIFIER_PUBLIC_KEY` default. No volume, no first-boot generation.
- Prod: seed in SSM under `/minister/prod/TLSN_ATTESTATION_KEY`, injected as
  env on the Lightsail box; only the container sees it. Never logged. Minister
  gets only the public key. Compromise blast radius = forged tlsn-attestation
  badges until rotation (rotate = new seed in SSM + new pubkey in Minister env;
  no VC re-issuance needed since Minister signs the badge VCs itself).
- The container keeps zero state; `restart: unless-stopped`, no volumes.

**Tests** (in-crate, no browser, no network):

- Unit: allowlist, caps, attestation payload/signature round-trip.
- Integration: in-process prover from the same `tlsn` crate over
  `tokio::io::duplex` against `tlsn-server-fixture` (exactly the upstream
  `examples/proxy.rs` topology) driving the full WS server -> signed
  attestation. This is the correctness proof for the protocol plumbing and
  doubles as the generator for a committed Minister-side fixture (below).

## 3. Minister-side changes

No Prisma schema change. The wizard-session JSON and the badge shape are
untouched; everything below is lib/route/plugin/env.

**New `apps/minister/src/lib/tlsn-attestation.ts`** (replaces
`tlsn-verifier.ts`): pure, local, no network.

```ts
verifyTlsnAttestation({ payload, signature }: { payload: string; signature: string })
  -> { serverName, sentBytes, recvBytes, nonce, time }   // throws on any failure
```

- Ed25519 verify with `node:crypto` (`crypto.verify(null, payloadBytes, key,
sig)`); build the KeyObject from `TLSN_VERIFIER_PUBLIC_KEY` (base64 raw 32B)
  by prefixing the standard 12-byte Ed25519 SPKI DER header
  (`302a300506032b6570032100`). Stdlib only, no new dependency.
- Missing/malformed `TLSN_VERIFIER_PUBLIC_KEY` -> throw (fail closed; there is
  no passthrough mode anymore).
- Zod-parse the payload after signature verification: `v === 1`, freshness
  (`time` within 10 minutes, hardcoded const), base64-decode sent/recv.
- Unit tests with a keypair from `crypto.generateKeyPairSync("ed25519")` plus
  the committed real fixture once step 5 produces it: happy path, bad
  signature, tampered payload, stale time, wrong pin.

**Plugin `apps/minister/src/plugins/tlsn-attestation/index.ts`**:

- `startWizard`: mint a `proofNonce` (reuse the existing `randomToken()`),
  stash it in wizard `data`, add it to the extension-action `params` alongside
  `url`, `submitUrl`, `sessionToken`.
- `handleStep`: input becomes `{ attestation: { payload, signature } }`. Call
  `verifyTlsnAttestation`, then check, in order: `payload.nonce ===
data.proofNonce` (binds the attestation to this wizard session - replay of
  someone else's attestation dies here), `payload.serverName === data.domain`,
  needle present in utf8-decoded `recvBytes`. Then audit-log + issue the badge
  exactly as today.

**Route `apps/minister/src/app/api/tlsn/submit/route.ts`**: `Body` becomes
`{ sessionToken, attestation: { payload: string, signature: string } }`; pass
`{ attestation }` as the plugin input. CORS allowlist, rate limiter, cookie
auth, and `resumeViaPendingToken` flow all unchanged.

**Env**: remove `TLSN_VERIFIER_URL` and `MINISTER_TLSN_VERIFIER_ALLOWED_HOSTS`
everywhere (env.ts if present, .env.example, compose). Add
`TLSN_VERIFIER_PUBLIC_KEY` (b64 raw 32B). Keep `TLSN_SUBMIT_ALLOWED_ORIGINS`.

**Compose**: single `tlsn-verifier` service on :7048 (WS + HTTP), env
`TLSN_ATTESTATION_KEY` / `TLSN_ALLOWED_TARGETS=example.com` / `RUST_LOG`;
healthcheck stays `GET /health`. `notary-server` and `notary_data` gone.

## 4. Extension retarget (`apps/extension`)

Start from cherry-picked `0466e30`, then:

- `package.json`: drop `tlsn-js`, add `tlsn-wasm@0.1.0-alpha.15` (exact pin).
  Keep esbuild + `build.mjs` (adjust the wasm asset copy to tlsn-wasm's pkg
  layout).
- New `src/io-channel.ts`: WebSocket -> IoChannel adapter (`read/write/close`,
  queue + backpressure cap). Reference implementation:
  `tlsn-extension/packages/common/src/io-channel.ts` (not on npm; ours is a
  fresh ~80-line file, same interface).
- `src/offscreen.ts` rewrite:
  1. `initialize(null, navigator.hardwareConcurrency)`; on failure retry
     `initialize(null, 1)`.
  2. Open `WS ${verifierUrl}/session`, send `register` with
     `{ maxSentData, maxRecvData, nonce }` (nonce from the wizard params),
     await `session_registered`.
  3. `fromWebSocket(`${verifierUrl}/verifier?sessionId=...`)` -> IoChannel.
  4. `new Prover({ server_name, mode: "Proxy", max_sent_data, max_recv_data,
network: "Latency" })` -> `setup(io)` -> `send_request(null, { method:
"GET", uri, headers: [["Host", host], ["Connection", "close"]] })`
     (null server_io is mandatory in proxy mode).
  5. `transcript()` -> reveal everything + `server_identity: true` via
     `reveal({ sent: [full range], recv: [full range], server_identity: true },
null)`. (Redaction/commit ranges are a Stage 8 concern for sensitive
     targets; the generic example.com demo reveals all. Confirm exact TS types
     against tlsn-wasm's shipped `.d.ts` at implementation time.)
  6. Await `session_completed` on the /session WS; forward
     `{ payload, signature }` to the background worker.
- `src/background.ts`: submit body becomes `{ sessionToken, attestation }`.
- `src/config.ts`: single `verifierUrl` (default `ws://localhost:7048`,
  esbuild-defined for prod, e.g. `wss://tlsn.ministry.id`). The verifier URL is
  extension build-time config, NOT taken from wizard params - a page must not
  be able to point the prover at an attacker's verifier. Delete
  `notaryUrl`/`websocketProxyUrl`.
- `manifest.json`: host permissions -> the verifier origin only; keep the
  `offscreen` permission and COOP/COEP keys (tlsn-wasm threads still use
  SharedArrayBuffer workers; whether proxy mode exercises them is exactly what
  the browser validation task settles - keep the isolation either way).
- Delete `src/encoding.ts` + test (no more hex->base64; attestation arrives
  base64).

## 5. Leftover validation tasks

1. **Regenerate the root `pnpm-lock.yaml`** - `apps/extension` is a workspace
   member; the tlsn-js -> tlsn-wasm swap must land as one commit with the
   lockfile (`pnpm install` at repo root), and `pnpm -r typecheck` green.
2. **Browser-validate the WASM prover path** - the standing gap from the held
   branch, unchanged in kind: load the built extension in Chrome, confirm
   offscreen document creation, tlsn-wasm init (worker spawn under
   COOP/COEP), and a full prove against the compose verifier. MV3 offscreen +
   bundler + SAB is the part no unit test covers; tlsn-extension is the
   working reference if the esbuild bundling fights back (they use webpack).
3. **Generate one real attestation fixture from a live prove run** - run the
   compose stack, drive the extension against `https://example.com/`, capture
   the `{ payload, signature, publicKey }` triple, commit it under
   `apps/minister/src/plugins/tlsn-attestation/__fixtures__/` and assert
   `verifyTlsnAttestation` accepts it. (The Rust integration test produces an
   equivalent fixture without a browser; commit that one first, replace with
   the live-run capture when task 2 completes.)
4. e2e: extend the existing wizard e2e only as far as "extension-action step
   renders with nonce+params" - full extension e2e stays manual (Playwright
   cannot drive MV3 offscreen documents worth the effort).

## 6. Risks and ordering

**Ordering** (each step lands green before the next):

1. Verifier rewrite + Rust unit/integration tests + Dockerfile + compose.
   Produces the synthetic attestation fixture. Biggest unknown first.
2. Minister seam: `tlsn-attestation.ts`, plugin, submit route, env,
   instrumentation cleanup, unit tests against the fixture.
3. Extension retarget + root lockfile regen (validation task 1).
4. Deletions: `services/notary`, `services/ws-proxy`, compose blocks, dead
   lib/env, docs (`CLAUDE.md`, `docs/status.md`, READMEs). Deleting last keeps
   the tree buildable at every commit.
5. Browser validation + live fixture (validation tasks 2-3). Then delete
   branch `feat/tlsn-proof-path`.

**Risks**

- _tlsn-wasm alpha.15 in an MV3 offscreen document_ - highest uncertainty;
  same class of risk the held branch already flagged for alpha.11 (worker
  inlining, SAB, COOP/COEP). Mitigant: tlsn-extension is a working MV3
  consumer of the exact same package version.
- _Open-proxy abuse_ - the verifier dials arbitrary `server_name:443` on the
  prover's say-so. The fail-closed allowlist is non-negotiable and must be in
  the first verifier commit, not a follow-up. Prod exposure also needs a
  Cloudflare tunnel ingress route (e.g. `tlsn.ministry.id` -> :7048) - infra
  task, and another place the known infra-repo compose drift can bite.
- _Proxy-mode trust model_ - proxy mode is sound only when the verifier is
  honest: it witnesses the ciphertext stream, so a lying prover can't swap
  servers, but a colluding verifier could. Fine here because verifier ==
  issuer (Ministry runs both, and Minister already trusts the attestation
  signature). Consequence: this verifier must never be offered as a
  third-party notary service, and its attestations mean nothing to anyone who
  doesn't trust Ministry. Document that in the service README.
- _Attestation replay/substitution_ - covered by nonce binding (per-wizard,
  single-use) + 10-minute freshness + pinned signer + cookie-authenticated
  submit. The signed payload carries no user identity by design; identity
  comes from the Minister session at submit time.
- _Upstream churn_ - alpha-series breaking changes are routine (this pivot is
  one). Git-tag pin + committed Cargo.lock + exact npm pin; the drift surface
  is confined to `services/tlsn-verifier` and `apps/extension`.
- _Key ops_ - a lost/rotated verifier seed only breaks NEW attestations
  (badges already issued are Minister-signed VCs). Rotation is env + pin swap,
  no migration. Do not put the seed anywhere except SSM/compose env.
