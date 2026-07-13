// Minister browser extension — background service worker.
//
// Orchestration only. The background worker is short-lived and cannot host the
// heavy TLSNotary WASM, so it delegates the actual proof to an offscreen
// document (see offscreen.ts) and keeps for itself: receiving the popup's
// request, ensuring the offscreen document exists, relaying the proof request,
// and submitting the finished presentation to Minister with the session cookie.

import { endpoints } from "./config.ts";
import {
  isProveMessage,
  type OffscreenRunResult,
  type ProveRequest,
  type ProveResult,
} from "./messages.ts";

const OFFSCREEN_PATH = "offscreen.html";

// Ensure exactly one offscreen document exists. Creating a second throws, and
// hasDocument() races under concurrent calls, so we serialize on a promise.
let creating: Promise<void> | undefined;

async function ensureOffscreenDocument(): Promise<void> {
  const contexts = await chrome.runtime.getContexts({
    contextTypes: [chrome.runtime.ContextType.OFFSCREEN_DOCUMENT],
  });
  if (Array.isArray(contexts) && contexts.length > 0) {
    return;
  }
  if (!creating) {
    creating = chrome.offscreen
      .createDocument({
        url: OFFSCREEN_PATH,
        // WORKERS: tlsn-js runs the prover across web workers.
        reasons: [chrome.offscreen.Reason.WORKERS],
        justification: "Run the TLSNotary WASM prover for a Minister badge proof.",
      })
      .finally(() => {
        creating = undefined;
      });
  }
  await creating;
}

async function performProof(req: ProveRequest): Promise<string> {
  await ensureOffscreenDocument();

  const result: OffscreenRunResult = await chrome.runtime.sendMessage({
    target: "offscreen",
    kind: "tlsn-run",
    request: {
      url: req.url,
      notaryUrl: endpoints.notaryUrl,
      websocketProxyUrl: endpoints.websocketProxyUrl,
    },
  });

  if (!result || result.ok !== true) {
    throw new Error(result?.error ?? "offscreen prover returned no result");
  }
  return result.presentationBase64;
}

async function submitPresentation(req: ProveRequest, presentationBase64: string): Promise<void> {
  const response = await fetch(req.submitUrl, {
    method: "POST",
    credentials: "include", // need the Minister session cookie
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      sessionToken: req.sessionToken,
      presentation: presentationBase64,
    }),
  });
  if (!response.ok) {
    throw new Error(
      `Minister submit endpoint returned ${response.status}: ${await response.text()}`,
    );
  }
}

// Popup -> background message router. Kept narrow on purpose; the surface area
// an extension exposes is part of its threat model.
chrome.runtime.onMessage.addListener((msg: unknown, _sender, sendResponse) => {
  if (!isProveMessage(msg)) {
    return false;
  }
  const req = msg.request;
  (async () => {
    try {
      const presentation = await performProof(req);
      await submitPresentation(req, presentation);
      sendResponse({ ok: true } satisfies ProveResult);
    } catch (err) {
      sendResponse({
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      } satisfies ProveResult);
    }
  })();
  return true; // keep the message channel open for the async response
});

export {};
