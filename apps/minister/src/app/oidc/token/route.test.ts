import { beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// /oidc/token tombstone refusal.
//
// A donor authorization code minted ~60s before an account merge must not
// redeem AFTER the merge and mint a live token on the tombstoned donor. The
// merge deletes the donor's codes inside its transaction; this route carries
// the second, independent closure: the user lookup selects `mergedIntoUserId`
// and refuses with `invalid_grant` when it is non-null. These tests isolate
// that check — every crypto/DB dependency is mocked so the tombstone branch is
// the only thing under test. A live (non-merged) user is the positive control
// proving the guard doesn't break the happy path.
// ---------------------------------------------------------------------------

const h = vi.hoisted(() => ({
  mintIdToken: vi.fn(async () => "id.token.jwt"),
  mintAccessToken: vi.fn(async () => "access.token.jwt"),
  audit: vi.fn(async () => {}),
  db: {
    oidcAuthorizationCode: {
      updateMany: vi.fn(async () => ({ count: 1 })),
      findUnique: vi.fn(),
    },
    user: { findUnique: vi.fn() },
    oidcAccessToken: { create: vi.fn(async () => ({})) },
  },
}));

vi.mock("@/lib/rate-limit", () => ({
  clientIpFrom: () => "test-ip",
  oidcTokenLimiter: { check: () => ({ allowed: true, retryAfterSeconds: 0 }) },
}));
vi.mock("@/lib/oidc-clients", () => ({
  // Public (PKCE-only) client: no secret to verify.
  findClient: vi.fn(async () => ({ clientId: "client_A", clientSecretHash: null })),
  verifyClientSecret: vi.fn(async () => true),
}));
vi.mock("@/lib/oidc-tokens", () => ({
  ACCESS_TOKEN_TTL: 3600,
  verifyPkceS256: () => true,
  mintIdToken: h.mintIdToken,
  mintAccessToken: h.mintAccessToken,
}));
vi.mock("@/lib/oidc-subject", () => ({ resolveSub: async () => "pairwise_sub" }));
vi.mock("@/lib/issuer", () => ({ getIssuer: async () => ({ token: {} }) }));
vi.mock("@/lib/oidc-claims", () => ({
  loadApprovedBadgeJwts: async () => [],
  loadProfileOverride: async () => null,
  resolveUserClaims: () => ({
    name: undefined,
    picture: undefined,
    sybilBucket: undefined,
    ministerBadges: [],
  }),
}));
vi.mock("@/lib/prisma", () => ({ prisma: h.db }));
vi.mock("@/lib/audit", () => ({ audit: h.audit }));

import { POST } from "./route";

const REDIRECT_URI = "https://rp.example/callback";

function storedCode(overrides: Record<string, unknown> = {}) {
  return {
    code: "the_code",
    clientId: "client_A",
    userId: "user_donor",
    redirectUri: REDIRECT_URI,
    scopes: ["openid"],
    approvedBadgeIds: [] as string[],
    profileName: false,
    profileAvatar: false,
    sybilScore: false,
    sybilBucket: null,
    nonce: "nonce_1",
    codeChallenge: "challenge",
    codeChallengeMethod: "S256",
    expiresAt: new Date(Date.now() + 60_000),
    consumedAt: null,
    ...overrides,
  };
}

function tokenRequest(): Request {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: "the_code",
    redirect_uri: REDIRECT_URI,
    code_verifier: "verifier",
    client_id: "client_A",
  });
  return new Request("https://issuer.example/oidc/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  h.db.oidcAuthorizationCode.updateMany.mockResolvedValue({ count: 1 });
  h.db.oidcAuthorizationCode.findUnique.mockResolvedValue(storedCode());
});

describe("POST /oidc/token tombstone refusal", () => {
  it("refuses invalid_grant when the code's user was merged, and mints nothing", async () => {
    h.db.user.findUnique.mockResolvedValue({
      id: "user_donor",
      displayName: null,
      avatarUrl: null,
      mergedIntoUserId: "user_survivor",
    });

    const res = await POST(tokenRequest());

    expect(res.status).toBe(400);
    const b = (await res.json()) as { error?: string };
    expect(b.error).toBe("invalid_grant");
    // No token of any kind may be minted or persisted for a tombstoned donor.
    expect(h.mintIdToken).not.toHaveBeenCalled();
    expect(h.mintAccessToken).not.toHaveBeenCalled();
    expect(h.db.oidcAccessToken.create).not.toHaveBeenCalled();
    // The refused redemption is audit-logged as an invalid_grant.
    expect(h.audit).toHaveBeenCalledWith(
      null,
      "oidc.token.invalid_grant",
      expect.objectContaining({ reason: "user_merged_tombstoned" }),
    );
  });

  it("still mints tokens for a live (non-merged) user — the guard is not over-broad", async () => {
    h.db.user.findUnique.mockResolvedValue({
      id: "user_donor",
      displayName: null,
      avatarUrl: null,
      mergedIntoUserId: null,
    });

    const res = await POST(tokenRequest());

    expect(res.status).toBe(200);
    const b = (await res.json()) as { id_token?: string; access_token?: string };
    expect(b.id_token).toBe("id.token.jwt");
    expect(b.access_token).toBe("access.token.jwt");
    expect(h.db.oidcAccessToken.create).toHaveBeenCalledTimes(1);
  });
});
