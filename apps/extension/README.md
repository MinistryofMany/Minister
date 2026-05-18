# Tessera browser extension

Performs TLSNotary proofs in the user's browser and submits the finalized presentation back to Tessera.

## Status

**Stage 6 — skeleton.** Manifest, background service worker, popup, and the message-routing surface are in place. The actual TLSNotary prover (`tlsn-js` WASM) is not yet integrated — that's the remaining piece for a real end-to-end flow.

## Architecture

```
   ┌────────────────────────────────┐
   │  Tessera page (browser tab)    │
   │  wizard step kind=extension-…  │
   └───────────────┬────────────────┘
                   │ user opens popup
                   ▼
   ┌────────────────────────────────┐                ┌──────────────────────┐
   │  Popup script                  │ ─── runtime ─▶ │  Background SW       │
   │  reads active wizard payload,  │   sendMessage  │  performs TLSNotary  │
   │  shows "Run proof" button      │                │  via tlsn-js (TBD)   │
   └────────────────────────────────┘                └────────────┬─────────┘
                                                                  │ WS tunnel
                                          ┌─────────────┐    ◀────┘
                                          │  ws-proxy   │ tunnels HTTPS
                                          └─────┬───────┘
                                                ▼
                                          ┌─────────────┐
                                          │  Target     │
                                          │  HTTPS host │
                                          └─────────────┘

                                          ┌─────────────┐
                                          │ notary-srv  │ co-signs TLS records
                                          └─────────────┘

                                                ▲
                                                │ finalized presentation
                                                │ POST /api/tlsn/submit
                                                │ { sessionToken, presentation }
                                                ▼
                                          ┌─────────────┐
                                          │  Tessera    │ resolves wizard,
                                          │  Next.js    │ calls tlsn-verifier
                                          └─────────────┘
```

## Loading in Chrome (dev)

1. `pnpm --filter @tessera/extension build` (currently typechecks only — no real bundle yet).
2. `chrome://extensions` → Developer mode → "Load unpacked" → select `apps/extension/`.
3. Click the Tessera icon in the toolbar. Popup says "Stage 6 — placeholder."

## What's left

- Integrate `tlsn-js` for the in-browser prover.
- Add an offscreen document for the WASM runtime (MV3 service workers can't run heavy crypto in the worker context).
- Wire the popup → background → submitUrl flow with progress UI.
- Auto-detect Tessera tabs and surface the active wizard step in the popup.
