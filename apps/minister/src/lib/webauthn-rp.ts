// WebAuthn Relaying Party ID, pinned.
//
// Auth.js's Passkey provider, left bare, derives the RP ID from the incoming
// request URL. Behind a reverse proxy that host comes from a client-supplied
// header (`x-forwarded-host`), so an attacker who can steer the host could make
// the RP ID vary per request — the credential scope a passkey binds to. Pin it
// instead: an explicit override wins, otherwise localhost dev uses the AUTH_URL
// hostname and production uses "ministry.id". Read from process.env directly
// (matching oidc-config.ts) so this stays usable from the auth module without
// widening the validated env schema.

const LOCALHOST_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

/**
 * The pinned WebAuthn RP ID. The RP ID must be a registrable-domain suffix of
 * the request origin, so it is a bare hostname (no scheme, no port).
 *
 * Resolution order:
 *   1. `MINISTER_WEBAUTHN_RP_ID` — explicit operator override (any non-default
 *      deployment host).
 *   2. localhost dev — the `AUTH_URL` hostname when it is a loopback host.
 *   3. production default — `ministry.id`.
 */
export function webauthnRelayingParty(): string {
  const override = process.env.MINISTER_WEBAUTHN_RP_ID?.trim();
  if (override) return override;

  const authUrl = process.env.AUTH_URL ?? process.env.NEXTAUTH_URL;
  if (authUrl) {
    try {
      const host = new URL(authUrl).hostname;
      if (LOCALHOST_HOSTS.has(host)) return host;
    } catch {
      // Malformed AUTH_URL — fall through to the production default rather than
      // trusting a value we could not parse.
    }
  }

  return "ministry.id";
}
