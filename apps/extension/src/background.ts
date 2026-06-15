// Minister browser extension — background service worker.
//
// Listens for messages from Minister pages (via the popup; MV3 doesn't
// allow direct content-script-from-arbitrary-page postMessage to
// background, so the bridge lives in the popup). When the user opens
// a wizard whose step is `kind: "extension-action"`, the popup picks
// up the in-flight action and walks the user through the proof.
//
// Stage 6 — the actual TLSNotary prover (tlsn-js WASM) is not yet
// wired. This file is the architectural placeholder; the prover lands
// alongside the WS-proxy + notary integration in a later commit.

interface ProveRequest {
  // The submitUrl the plugin embedded in extension-action.payload.params
  // (under TLSN, this is `/api/tlsn/submit` on the Minister origin).
  submitUrl: string;
  // The Minister-side session token; we echo it back as `sessionToken`
  // in the submit body so Minister resolves the right wizard session.
  sessionToken: string;
  // The HTTPS endpoint the user is attesting against. tlsn-js opens a
  // session against this through the ws-proxy and asks the notary for
  // co-signature.
  url: string;
}

async function performProof(_req: ProveRequest): Promise<string> {
  // TODO(stage-6+): integrate `tlsn-js` to run the prover in an
  // offscreen document, talk to the ws-proxy, exchange handshake with
  // the notary, return the finalized presentation as a base64 string.
  throw new Error(
    "TLSNotary prover not yet wired. Background skeleton is in place; " +
      "the prover lands when tlsn-js is integrated.",
  );
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

// Popup → background message router. Kept narrow on purpose; the
// surface area an extension exposes is part of its threat model.
chrome.runtime.onMessage.addListener((msg: unknown, _sender, sendResponse) => {
  if (!msg || typeof msg !== "object" || !("kind" in msg) || msg.kind !== "tlsn-prove") {
    return false;
  }
  const req = (msg as unknown as { request: ProveRequest }).request;
  (async () => {
    try {
      const presentation = await performProof(req);
      await submitPresentation(req, presentation);
      sendResponse({ ok: true });
    } catch (err) {
      sendResponse({
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  })();
  return true; // keep the message channel open for the async response
});

export {};
