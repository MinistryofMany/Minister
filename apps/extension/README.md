# Minister browser extension

Performs TLSNotary proofs in the user's browser and submits the finalized presentation back to Minister.

## Status

**Stage 6 — prover integrated (pending browser validation).** The `tlsn-js` prover runs in an offscreen document, tunnels its TLS session through the `ws-proxy`, gets a co-signature from the `notary-server`, and hands the finalized presentation (as base64) back to the background worker, which POSTs it to `/api/tlsn/submit`. The TypeScript typechecks, the module graph bundles, and the encoding helper is unit-tested. What still needs a real Chrome to confirm is the WASM asset/worker wiring and SharedArrayBuffer runtime (see "What's left").

## Architecture

```
   Minister page (wizard, extension-action step)
                   │ user opens popup, clicks "Run proof"
                   ▼
   Popup ──runtime.sendMessage {kind:"tlsn-prove"}──▶ Background SW
                                                        │ ensures offscreen doc,
                                                        │ relays request
                                                        ▼
                                                   Offscreen document
                                                   tlsn-js WASM prover
                                              ┌─────────┴──────────┐
                                              │ ws-proxy (?token=host)  → target HTTPS host
                                              │ notary-server           → co-signs TLS records
                                              └─────────┬──────────┘
                                                        │ presentation (hex → base64)
                                                        ▼
                                   Background SW ──POST /api/tlsn/submit──▶ Minister
                                   { sessionToken, presentation }
```

- **background.ts** — orchestration only (short-lived worker can't host heavy WASM): receives the popup request, ensures the offscreen document exists (`chrome.offscreen`), relays the proof request, submits the result with the Minister session cookie.
- **offscreen.ts** — hosts the `tlsn-js` WASM prover. `Prover.notarize({ url, notaryUrl, websocketProxyUrl })` runs the whole flow and returns a `PresentationJSON`; `presentation.data` is hex(bincode(Presentation)), which we convert to base64 for the verifier.
- **encoding.ts** — pure hex↔base64 over the exact presentation bytes (`hexToBase64`). Unit-tested.
- **config.ts** — notary + ws-proxy URLs, overridable at bundle time via `MINISTER_NOTARY_URL` / `MINISTER_WS_PROXY_URL`.
- **messages.ts** — discriminated message contracts across popup/background/offscreen.

## Version pinning

`tlsn-js@0.1.0-alpha.11.0` (→ `tlsn-wasm@0.1.0-alpha.11`) matches the pinned `notary-server` image and the `tlsn-core` tag the `tlsn-verifier` sidecar uses. All four MUST move together on any bump. Notes for the alpha.11 pin:

- The presentation ALWAYS includes the server-identity proof (wasm `build_presentation` adds it unconditionally), so the verified output carries a server name — which the verifier requires. alpha.12+ makes this opt-in via a `serverIdentity` flag; pass it when bumping.
- `Prover.notarize` appends `?token=<hostname>` to `websocketProxyUrl` itself, which is exactly the `ws-proxy` protocol — so `MINISTER_WS_PROXY_URL` must be the base ws URL with no query string.
- The default reveal discloses the **entire** transcript. Fine for the generic `tlsn-attestation` demo; a plugin proving against a sensitive host (id.me) must pass a `commit` that redacts request auth headers / response PII (Stage 8 follow-up).

## Build & test

```
pnpm install          # from the Minister workspace root (adds tlsn-js, esbuild)
pnpm --filter @minister/extension typecheck
pnpm --filter @minister/extension test        # node --test, encoding helper
pnpm --filter @minister/extension build       # esbuild → dist/
```

`build` bundles `background`/`popup`/`offscreen` into `dist/`, copies the manifest + HTML + icons, and copies the tlsn-wasm assets (`tlsn_wasm_bg.wasm`, `snippets/`) so the prover's `import.meta.url`-relative lookups resolve. Load `dist/` via `chrome://extensions` → Developer mode → "Load unpacked".

The manifest sets `cross_origin_embedder_policy: require-corp` + `cross_origin_opener_policy: same-origin` so the offscreen document is cross-origin isolated (tlsn-wasm needs `SharedArrayBuffer` for its worker threads).

## What's left (needs a running Chrome to validate)

1. **WASM worker path.** esbuild inlines the tlsn-wasm JS glue into `offscreen.js`; the copied `snippets/.../spawn.js` dynamic-imports `../../../tlsn_wasm.js`, which no longer exists at that path. Options: ship `tlsn_wasm.js` unbundled and mark `tlsn-wasm` external, or patch the snippet import. Confirm the rayon worker spawns and `tlsn_wasm_bg.wasm` fetches from `dist/`.
2. **SharedArrayBuffer / COOP-COEP.** Verify the offscreen document is actually cross-origin isolated under the manifest keys and that shared `WebAssembly.Memory` initializes.
3. **Popup → active wizard wiring.** popup.ts still needs to read the active Minister tab's `extension-action` step payload (submitUrl, sessionToken, url) and send the `tlsn-prove` message. Today it is a static placeholder.
4. **End-to-end** against the compose stack (notary + ws-proxy + tlsn-verifier in `real` mode) with a real target, plus notary-key pinning (`TLSN_NOTARY_PUBLIC_KEY`) wired from the notary's published key.
