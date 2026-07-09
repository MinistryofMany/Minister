// Pure, network-free helpers for the Steam OpenID 2.0 flow, kept out of index.ts
// so the assertion parse and the check_authentication request-building are
// unit-testable without hitting Steam.

// The one Steam OpenID endpoint. We POST the check_authentication back HERE
// (hardcoded), never to the `openid.op_endpoint` the callback carried — trusting
// that field would let a forged callback point us at an attacker server that
// happily answers "is_valid:true".
export const STEAM_OPENID_ENDPOINT = "https://steamcommunity.com/openid/login";

// A Steam claimed_id is exactly `https://steamcommunity.com/openid/id/<17-digit
// steamid64>`. Anchored + host-pinned so a look-alike host can't smuggle a
// different identity.
const CLAIMED_ID_RE = /^https:\/\/steamcommunity\.com\/openid\/id\/([0-9]{17})$/u;

// Extract the immutable steamid64 from a claimed_id, or null if it doesn't match
// the exact expected shape.
export function parseSteamId(claimedId: string): string | null {
  const m = CLAIMED_ID_RE.exec(claimedId);
  return m ? m[1]! : null;
}

// Collect only the `openid.*` params from the callback into the body we POST
// back for verification, echoing each value VERBATIM (the signature covers them)
// and flipping the mode to check_authentication. Any non-openid param (e.g. our
// own `state`) is dropped — it is not part of what Steam signed.
export function buildCheckAuthParams(openidParams: Record<string, string>): URLSearchParams {
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(openidParams)) {
    if (key.startsWith("openid.")) body.set(key, value);
  }
  body.set("openid.mode", "check_authentication");
  return body;
}

// Steam's check_authentication response is a key:value line list. A genuine,
// unforged assertion contains the exact line `is_valid:true`.
export function assertionIsValid(responseBody: string): boolean {
  return responseBody.split(/\r?\n/u).some((line) => line.trim() === "is_valid:true");
}

// OpenID 2.0 §10.1/§11.4: the RP MUST confirm the fields it relies on are
// actually covered by the signature. check_authentication only attests that the
// signature is valid over WHATEVER `openid.signed` names — a forged callback can
// present a reduced `signed` list (dropping claimed_id or return_to), swap those
// now-unsigned fields, and still get back `is_valid:true`. So we require every
// field we trust to be present in the comma-separated `openid.signed` set.
export const REQUIRED_SIGNED_FIELDS = [
  "claimed_id",
  "identity",
  "return_to",
  "response_nonce",
  "assoc_handle",
  "op_endpoint",
] as const;

// True only when `openid.signed` (comma-separated, `openid.`-prefix-stripped
// field names) covers every field in REQUIRED_SIGNED_FIELDS. Missing/empty ⇒
// false (fail closed).
export function signedFieldsCoverRequired(signed: string | undefined): boolean {
  if (!signed) return false;
  const present = new Set(signed.split(",").map((f) => f.trim()));
  return REQUIRED_SIGNED_FIELDS.every((f) => present.has(f));
}
