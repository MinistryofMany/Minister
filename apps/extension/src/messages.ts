// Message contracts shared across the extension's contexts (popup ->
// background -> offscreen). Kept narrow and discriminated so each listener can
// reject anything it does not own — the message surface is part of the threat
// model.

// popup -> background: start a proof for an in-flight wizard action.
export interface ProveRequest {
  // The submitUrl the plugin embedded in extension-action.payload.params
  // (under TLSN, this is `/api/tlsn/submit` on the Minister origin).
  submitUrl: string;
  // The Minister-side session token; echoed back as `sessionToken` in the
  // submit body so Minister resolves the right wizard session.
  sessionToken: string;
  // The HTTPS endpoint being attested. tlsn-js opens a session against this
  // host through the ws-proxy and asks the notary to co-sign.
  url: string;
}

export interface ProveMessage {
  kind: "tlsn-prove";
  request: ProveRequest;
}

export interface ProveResult {
  ok: boolean;
  error?: string;
}

// background -> offscreen: run the actual WASM prover.
export interface OffscreenRunMessage {
  target: "offscreen";
  kind: "tlsn-run";
  request: {
    url: string;
    notaryUrl: string;
    websocketProxyUrl: string;
  };
}

export type OffscreenRunResult =
  { ok: true; presentationBase64: string } | { ok: false; error: string };

export function isProveMessage(msg: unknown): msg is ProveMessage {
  return (
    typeof msg === "object" &&
    msg !== null &&
    (msg as { kind?: unknown }).kind === "tlsn-prove" &&
    typeof (msg as { request?: unknown }).request === "object"
  );
}

export function isOffscreenRunMessage(msg: unknown): msg is OffscreenRunMessage {
  return (
    typeof msg === "object" &&
    msg !== null &&
    (msg as { target?: unknown }).target === "offscreen" &&
    (msg as { kind?: unknown }).kind === "tlsn-run"
  );
}
