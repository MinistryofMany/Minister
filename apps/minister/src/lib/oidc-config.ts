import { knownBadgeTypes } from "@minister/shared";

// OIDC discovery / issuer config. The OIDC `issuer` is the URL Minister
// is reachable on (not the did:web identifier from packages/vc — that's
// for VCs). We reuse AUTH_URL since Auth.js already requires it.
//
// All endpoint paths are relative to the issuer; we compose absolute
// URLs on the fly. Anything that would require a stage we haven't built
// (refresh_token, introspection, registration) is omitted from the
// `*_supported` arrays.

export function oidcIssuerUrl(): string {
  const url = process.env.AUTH_URL ?? process.env.NEXTAUTH_URL;
  if (!url) {
    throw new Error("OIDC issuer URL not set — configure AUTH_URL");
  }
  // Strip trailing slash for canonical comparison.
  return url.replace(/\/$/, "");
}

export function badgeScopes(): string[] {
  return knownBadgeTypes().map((t) => `badge:${t}`);
}

// Returned by GET /.well-known/openid-configuration. Shape per RFC 8414
// / OIDC Discovery 1.0 §3.
export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  response_types_supported: string[];
  grant_types_supported: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
  scopes_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  code_challenge_methods_supported: string[];
  claims_supported: string[];
}

export function getOidcDiscovery(): OidcDiscovery {
  const issuer = oidcIssuerUrl();
  return {
    issuer,
    authorization_endpoint: `${issuer}/oidc/authorize`,
    token_endpoint: `${issuer}/oidc/token`,
    userinfo_endpoint: `${issuer}/oidc/userinfo`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    // Pairwise pseudonymous `sub` derived from HMAC(userId || clientId).
    // Public sub-types intentionally absent — Minister's whole point is
    // unlinkability across RPs.
    subject_types_supported: ["pairwise"],
    id_token_signing_alg_values_supported: ["EdDSA"],
    scopes_supported: ["openid", "profile", ...badgeScopes()],
    token_endpoint_auth_methods_supported: [
      "client_secret_basic",
      "client_secret_post",
      "none", // PKCE-only public clients
    ],
    code_challenge_methods_supported: ["S256"],
    claims_supported: ["sub", "iss", "aud", "iat", "exp", "nonce", "name", "picture", "minister_badges"],
  };
}
