import { Resolver } from "node:dns/promises";

// The two independent public recursive resolvers we corroborate against:
// Cloudflare (1.1.1.1) and Google (8.8.8.8). A single resolver can be poisoned
// into returning an attacker-chosen answer, which for this badge means minting a
// `domain-control` claim over a domain the requester does not own. Requiring both
// to independently return the challenge token raises the bar to poisoning two
// unrelated resolver paths at once.
//
// DEPLOYMENT NOTE: this makes outbound DNS to 1.1.1.1 AND 8.8.8.8 (UDP/TCP 53) a
// hard runtime dependency of the domain-control badge. If the box cannot reach
// both, verification always fails closed (retryable) and no badge is ever issued.
export const CORROBORATING_RESOLVERS = ["1.1.1.1", "8.8.8.8"] as const;

// Resolve TXT for `host` against one specific public resolver, never the box's
// default/system resolver. A fresh Resolver per call keeps the pinned server list
// isolated (no shared global mutation) and DNS-ONLY — a TXT lookup, never an HTTP
// fetch, so there is no SSRF surface and no new dependency (node:dns is built-in).
export async function resolveTxtVia(server: string, host: string): Promise<string[][]> {
  const resolver = new Resolver();
  resolver.setServers([server]);
  return resolver.resolveTxt(host);
}
