// Offscreen document — hosts the tlsn-js WASM prover.
//
// Why offscreen: an MV3 background service worker is short-lived and cannot
// reliably host the multi-threaded TLSNotary WASM (it needs a real document
// with workers + SharedArrayBuffer, which requires the cross-origin isolation
// declared in manifest.json's COOP/COEP keys). The background worker owns
// orchestration + network submission; this document owns only the proving.

import init, { Prover } from "tlsn-js";

import { hexToBase64 } from "./encoding.ts";
import { isOffscreenRunMessage, type OffscreenRunResult } from "./messages.ts";

let wasmReady: Promise<void> | undefined;

// Initialize the WASM module exactly once, lazily.
function ensureWasm(): Promise<void> {
  if (!wasmReady) {
    wasmReady = init({ loggingLevel: "Info" });
  }
  return wasmReady;
}

async function runProof(req: {
  url: string;
  notaryUrl: string;
  websocketProxyUrl: string;
}): Promise<string> {
  await ensureWasm();

  // In tlsn-js alpha.11 the presentation ALWAYS includes the server-identity
  // proof (wasm `build_presentation` unconditionally adds it), so the verified
  // output carries a server name — which the Minister tlsn-verifier requires to
  // honor `expectedDomain`. (alpha.12+ makes this opt-in via `serverIdentity`;
  // when bumping the pin, pass `serverIdentity: true` here.)
  //
  // NOTE: the default commit/reveal discloses the ENTIRE transcript. That is
  // fine for the generic tlsn-attestation demo (example.com), but a plugin
  // proving against a sensitive host (id.me) MUST pass a `commit` that redacts
  // request auth headers and any response PII before revealing. Tracked as a
  // follow-up for the specialized plugins (Stage 8).
  const presentation = await Prover.notarize({
    url: req.url,
    notaryUrl: req.notaryUrl,
    websocketProxyUrl: req.websocketProxyUrl,
    method: "GET",
  });

  // `presentation.data` is hex(bincode(Presentation)); the verifier wants
  // base64(bincode(Presentation)).
  return hexToBase64(presentation.data);
}

chrome.runtime.onMessage.addListener((msg: unknown, _sender, sendResponse) => {
  if (!isOffscreenRunMessage(msg)) {
    return false;
  }
  (async () => {
    try {
      const presentationBase64 = await runProof(msg.request);
      sendResponse({ ok: true, presentationBase64 } satisfies OffscreenRunResult);
    } catch (err) {
      sendResponse({
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      } satisfies OffscreenRunResult);
    }
  })();
  return true; // async response
});
