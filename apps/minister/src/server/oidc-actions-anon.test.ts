import { beforeEach, describe, expect, it, vi } from "vitest";

// Unit coverage for approveConsent's anon-identity fragment-delivery branch
// (anon-identity master spec §8.2). The surrounding disclosure/minimization
// machinery is exercised by oidc-actions.test.ts + the Playwright e2e; this
// isolates the delivery decision and asserts the authorization code's security
// properties are UNCHANGED (PKCE S256 + state bound, 60s TTL, single-use,
// transient). Everything approveConsent touches is mocked (the real env module
// parses process.env at import; the real session module pulls in @/auth).

const h = vi.hoisted(() => {
  class RedirectError extends Error {
    constructor(readonly url: string) {
      super("REDIRECT");
    }
  }
  return {
    RedirectError,
    env: { ANON_IDENTITY_ENABLED: false as boolean },
    session: { user: { id: "user-1" } } as { user: { id: string } },
    request: {
      clientId: "mc_test",
      scopes: ["openid"],
      redirectUri: "https://rp.example/cb",
      state: "state-xyz",
      nonce: "nonce-abc",
      codeChallenge: "challenge-123",
      codeChallengeMethod: "S256",
      policy: null,
    },
    createdCode: null as null | Record<string, unknown>,
    anonAppId: null as string | null,
    audit: vi.fn(async () => {}),
  };
});

vi.mock("@/env", () => ({ env: h.env }));
vi.mock("@/lib/audit", () => ({ audit: h.audit }));
vi.mock("@/lib/session", () => ({ getCurrentSession: vi.fn(async () => h.session) }));
vi.mock("@/lib/oidc-request-token", () => ({ verifyOidcRequest: vi.fn(async () => h.request) }));
vi.mock("@/lib/issuer", () => ({ getIssuer: vi.fn(async () => ({ did: "did:web:test" })) }));
vi.mock("@/lib/anonymity-sets", () => ({ holderCountsByType: vi.fn(async () => new Map()) }));
vi.mock("@/lib/sybil-config", () => ({ loadSybilScoringConfig: vi.fn(async () => ({})) }));
vi.mock("@/lib/sybil-score", () => ({ sybilScore: vi.fn(() => ({ bucket: 0 })) }));
vi.mock("@/lib/oidc-grants", () => ({
  loadGrant: vi.fn(async () => ({
    badgeIds: [],
    badgeTypes: [],
    profileName: false,
    profileAvatar: false,
    sybilScore: false,
  })),
  upsertGrant: vi.fn(async () => {}),
}));
vi.mock("@/server/oidc-consent-minimize", () => ({
  minimizeToPolicy: vi.fn(() => []),
  toPolicyUserBadge: vi.fn((b: unknown) => b),
}));
vi.mock("@/server/profile-validation", () => ({
  normalizeProfileInput: vi.fn(() => ({ displayName: null, avatarUrl: null })),
}));
vi.mock("@/server/wizard-helpers", () => ({ effectiveScopes: vi.fn(() => ["openid"]) }));
vi.mock("@/lib/oidc-authorize", () => ({
  buildSuccessRedirect: (redirectUri: string, code: string, state: string) => {
    const u = new URL(redirectUri);
    u.searchParams.set("code", code);
    u.searchParams.set("state", state);
    return u.toString();
  },
  buildErrorRedirect: (redirectUri: string) => redirectUri,
}));
vi.mock("next/navigation", () => ({
  redirect: (url: string) => {
    throw new h.RedirectError(url);
  },
}));
vi.mock("@/lib/prisma", () => ({
  prisma: {
    // Interactive transaction: run the callback against a tx double that
    // captures the created auth-code row.
    $transaction: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) =>
      fn({
        oidcAuthorizationCode: {
          create: vi.fn(async (args: { data: Record<string, unknown> }) => {
            h.createdCode = args.data;
            return args.data;
          }),
        },
        oidcProfileOverride: { upsert: vi.fn(async () => ({})) },
      }),
    ),
    oidcClient: { findUnique: vi.fn(async () => ({ anonAppId: h.anonAppId })) },
    badge: { findMany: vi.fn(async () => []) },
  },
}));

import { approveConsent } from "@/server/oidc-actions";

const INPUT = {
  requestToken: "tok",
  approvedBadgeIds: [] as string[],
  approveName: false,
  approveAvatar: false,
  approveSybilScore: false,
};

beforeEach(() => {
  vi.clearAllMocks();
  h.env.ANON_IDENTITY_ENABLED = false;
  h.anonAppId = null;
  h.createdCode = null;
});

describe("approveConsent — authorization code properties (unchanged on both paths)", () => {
  it("mints a code that is PKCE(S256)+state/nonce-bound with a 60s TTL and no consumedAt", async () => {
    // Non-anon path: redirect() is called (throws our sentinel).
    await expect(approveConsent(INPUT)).rejects.toBeInstanceOf(h.RedirectError);

    const code = h.createdCode!;
    expect(code.codeChallengeMethod).toBe("S256");
    expect(code.codeChallenge).toBe("challenge-123");
    expect(code.nonce).toBe("nonce-abc");
    expect(code.consumedAt).toBeUndefined(); // single-use: unconsumed at mint
    // 43-char base64url authorization code (32 random bytes).
    expect(code.code).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // 60-second TTL.
    const ttlMs = (code.expiresAt as Date).getTime() - Date.now();
    expect(ttlMs).toBeGreaterThan(58_000);
    expect(ttlMs).toBeLessThanOrEqual(60_000);
  });
});

describe("approveConsent — anon fragment delivery decision (§8.2)", () => {
  it("flag ON + anon-enabled client → RETURNS {redirectTo, anonAppId}, no server redirect", async () => {
    h.env.ANON_IDENTITY_ENABLED = true;
    h.anonAppId = "deforum";

    const result = await approveConsent(INPUT);
    expect(result).toBeDefined();
    if (!result || "error" in result || !("redirectTo" in result)) {
      throw new Error(`expected a redirectTo result, got ${JSON.stringify(result)}`);
    }
    expect(result.anonAppId).toBe("deforum");
    // Same success URL: carries the single-use code and the bound state.
    const url = new URL(result.redirectTo);
    expect(url.origin + url.pathname).toBe("https://rp.example/cb");
    expect(url.searchParams.get("code")).toBe(h.createdCode!.code);
    expect(url.searchParams.get("state")).toBe("state-xyz");
    // The fragment (the per-app secret) is NEVER built server-side.
    expect(result.redirectTo).not.toContain("#");
  });

  it("flag ON + NON-anon client (anonAppId null) → server redirect, no return", async () => {
    h.env.ANON_IDENTITY_ENABLED = true;
    h.anonAppId = null;
    await expect(approveConsent(INPUT)).rejects.toBeInstanceOf(h.RedirectError);
  });

  it("flag OFF + anon-enabled client → server redirect (feature inert)", async () => {
    h.env.ANON_IDENTITY_ENABLED = false;
    h.anonAppId = "deforum"; // set, but the flag gates it off
    await expect(approveConsent(INPUT)).rejects.toBeInstanceOf(h.RedirectError);
    // The client is not even queried when the flag is off.
  });
});
