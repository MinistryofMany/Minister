import { z } from "zod";

import { findClient, isRegisteredRedirectUri } from "@/lib/oidc-clients";
import {
  MAX_POLICY_DEPTH,
  parsePolicy,
  policyBadgeTypes,
  policyDepth,
  type PolicyNode,
} from "@/lib/oidc-policy";

// Parsed, validated /oidc/authorize parameters. Once a value of this
// type exists, every requirement from RFC 6749 + OIDC Core 1.0 +
// CLAUDE.md's "Required security" list has been checked, EXCEPT user
// consent (which the UI handles). Pass it to consent rendering and
// authorization-code minting without re-checking.
export interface ValidAuthorizeRequest {
  clientId: string;
  clientName: string;
  allowedScopes: string[];
  redirectUri: string;
  scopes: string[];
  state: string;
  nonce: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  // Phase-2 OR/threshold selection. Present when the RP sent a
  // `minister_policy` authorize param carrying the room's requirement
  // subtree; null for today's flat per-scope flow. Validated here
  // (parsed, strict-schema'd, types ⊆ scope, size/depth-bounded) so the
  // signed request token carries a trusted policy into consent.
  policy: PolicyNode | null;
}

// Caps on the inbound minister_policy payload, to keep a crafted policy
// from blowing up the consent path. The param travels on the
// front-channel authorize URL; a few hundred bytes is the realistic
// size, so 4 KB is generous headroom while still bounded.
const MAX_POLICY_BYTES = 4096;

// Validation produces either a valid request, a "redirect to RP with
// error" outcome (we have a trusted redirect_uri, so error reporting
// goes back to the RP), or a "render error to the end user" outcome
// (client_id / redirect_uri itself is bad, redirecting could be an
// open-redirect attack).
export type AuthorizeValidationResult =
  | { kind: "ok"; request: ValidAuthorizeRequest }
  | {
      kind: "redirect-error";
      redirectUri: string;
      state: string | null;
      error: OidcError;
      description: string;
    }
  | {
      kind: "fatal";
      title: string;
      description: string;
    };

export type OidcError =
  | "invalid_request"
  | "unauthorized_client"
  | "access_denied"
  | "unsupported_response_type"
  | "invalid_scope"
  | "server_error"
  | "temporarily_unavailable";

// Build a redirect URL back to the RP carrying error/state per RFC 6749
// §4.1.2.1.
export function buildErrorRedirect(
  redirectUri: string,
  error: OidcError,
  description: string,
  state: string | null,
): string {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  url.searchParams.set("error_description", description);
  if (state) url.searchParams.set("state", state);
  return url.toString();
}

// Build the success redirect carrying code/state per RFC 6749 §4.1.2.
export function buildSuccessRedirect(redirectUri: string, code: string, state: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set("code", code);
  url.searchParams.set("state", state);
  return url.toString();
}

const Required = z.string().min(1);
const ChallengeMethod = z.literal("S256");

export async function validateAuthorizeRequest(
  raw: URLSearchParams,
): Promise<AuthorizeValidationResult> {
  // Step 1: client_id must exist. Without it we can't proceed at all.
  const clientId = raw.get("client_id");
  if (!clientId) {
    return {
      kind: "fatal",
      title: "Missing client_id",
      description: "This /oidc/authorize request did not include a client_id.",
    };
  }

  const client = await findClient(clientId);
  if (!client) {
    // Unknown client — render an error to the user. Do NOT redirect:
    // the redirect_uri here is attacker-controlled.
    return {
      kind: "fatal",
      title: "Unknown client",
      description: `No OIDC client is registered with id ${clientId}.`,
    };
  }

  // Step 2: redirect_uri must exact-match a registered URI.
  const redirectUri = raw.get("redirect_uri");
  if (!redirectUri || !isRegisteredRedirectUri(client, redirectUri)) {
    return {
      kind: "fatal",
      title: "Invalid redirect URI",
      description:
        "The redirect_uri does not match any registered URI for this client. The relying party's configuration is wrong.",
    };
  }

  // From here on, redirect_uri is trusted and validation errors can
  // safely redirect back to it with error= params.
  const state = raw.get("state");

  // Step 3: response_type. We only support `code`.
  const responseType = raw.get("response_type");
  if (responseType !== "code") {
    return {
      kind: "redirect-error",
      redirectUri,
      state,
      error: "unsupported_response_type",
      description: responseType
        ? `response_type=${responseType} is not supported; use 'code'.`
        : "response_type is required",
    };
  }

  // Step 4: state + nonce required.
  if (!Required.safeParse(state).success) {
    return {
      kind: "redirect-error",
      redirectUri,
      state: null,
      error: "invalid_request",
      description: "state is required",
    };
  }
  const nonce = raw.get("nonce");
  if (!Required.safeParse(nonce).success) {
    return {
      kind: "redirect-error",
      redirectUri,
      state,
      error: "invalid_request",
      description: "nonce is required",
    };
  }

  // Step 5: PKCE — required, S256 only.
  const codeChallenge = raw.get("code_challenge");
  if (!Required.safeParse(codeChallenge).success) {
    return {
      kind: "redirect-error",
      redirectUri,
      state,
      error: "invalid_request",
      description: "code_challenge is required (PKCE is mandatory)",
    };
  }
  const codeChallengeMethod = raw.get("code_challenge_method");
  if (!ChallengeMethod.safeParse(codeChallengeMethod).success) {
    return {
      kind: "redirect-error",
      redirectUri,
      state,
      error: "invalid_request",
      description: "code_challenge_method=S256 is required",
    };
  }

  // Step 6: scope. Must include `openid`, must be subset of
  // client.allowedScopes.
  const scopeStr = raw.get("scope") ?? "";
  const scopes = scopeStr.split(/\s+/).filter(Boolean);
  if (!scopes.includes("openid")) {
    return {
      kind: "redirect-error",
      redirectUri,
      state,
      error: "invalid_scope",
      description: "openid scope is required",
    };
  }
  const disallowed = scopes.filter((s) => !client.allowedScopes.includes(s));
  if (disallowed.length > 0) {
    return {
      kind: "redirect-error",
      redirectUri,
      state,
      error: "invalid_scope",
      description: `client is not authorized for scope(s): ${disallowed.join(", ")}`,
    };
  }

  // Step 7: optional minister_policy (Phase-2 OR/threshold selection).
  // Fail-closed at every sub-step — never proceed with an
  // unparseable/invalid/over-broad policy.
  const policyResult = parseMinisterPolicy(raw.get("minister_policy"), scopes);
  if (policyResult.kind === "error") {
    return {
      kind: "redirect-error",
      redirectUri,
      state,
      error: policyResult.error,
      description: policyResult.description,
    };
  }

  // All clear.
  // Refinements above narrowed everything to strings; we know they're
  // non-null from the safeParse checks. Help TS along.
  return {
    kind: "ok",
    request: {
      clientId,
      clientName: client.name,
      allowedScopes: client.allowedScopes,
      redirectUri,
      scopes,
      state: state as string,
      nonce: nonce as string,
      codeChallenge: codeChallenge as string,
      codeChallengeMethod: "S256",
      policy: policyResult.policy,
    },
  };
}

type PolicyParseResult =
  | { kind: "ok"; policy: PolicyNode | null }
  | { kind: "error"; error: OidcError; description: string };

// Parse + validate the optional minister_policy authorize param.
//   absent           → { policy: null }            (today's flat flow)
//   bad base64/JSON  → invalid_request             (malformed)
//   too big          → invalid_request             (DoS guard)
//   not a policy     → invalid_scope               (schema reject)
//   too deeply nested→ invalid_request             (DoS guard)
//   type ∉ scope     → invalid_scope               (can't widen the menu)
//
// Enforcing policy types ⊆ requested scope (which is already ⊆
// client.allowedScopes, checked above) means the policy can only
// STRUCTURE the already-permitted scope menu, never smuggle in a type the
// RP isn't authorized to ask about.
function parseMinisterPolicy(rawParam: string | null, scopes: string[]): PolicyParseResult {
  if (rawParam === null || rawParam.length === 0) {
    return { kind: "ok", policy: null };
  }

  let json: string;
  try {
    json = Buffer.from(rawParam, "base64url").toString("utf8");
  } catch {
    return { kind: "error", error: "invalid_request", description: "minister_policy is malformed" };
  }
  if (json.length > MAX_POLICY_BYTES) {
    return {
      kind: "error",
      error: "invalid_request",
      description: "minister_policy is too large",
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return { kind: "error", error: "invalid_request", description: "minister_policy is malformed" };
  }

  let policy: PolicyNode;
  try {
    policy = parsePolicy(parsed);
  } catch {
    return {
      kind: "error",
      error: "invalid_scope",
      description: "minister_policy is not a valid policy",
    };
  }

  if (policyDepth(policy) > MAX_POLICY_DEPTH) {
    return {
      kind: "error",
      error: "invalid_request",
      description: "minister_policy is nested too deeply",
    };
  }

  const requestedBadgeTypes = new Set(
    scopes.filter((s) => s.startsWith("badge:")).map((s) => s.slice("badge:".length)),
  );
  for (const type of policyBadgeTypes(policy)) {
    if (!requestedBadgeTypes.has(type)) {
      return {
        kind: "error",
        error: "invalid_scope",
        description: `minister_policy references badge type not in scope: ${type}`,
      };
    }
  }

  return { kind: "ok", policy };
}
