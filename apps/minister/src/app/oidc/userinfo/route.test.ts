import { SignJWT, exportJWK, generateKeyPair, type JWK, type KeyLike } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import type { Issuer } from "@minister/vc";

import { mintAccessToken } from "@/lib/oidc-tokens";
import { oidcIssuerUrl } from "@/lib/oidc-config";

// /oidc/userinfo verifies the bearer ACCESS token. Access tokens are signed by
// `mintAccessToken` with the in-process TOKEN key (#key-3, `issuer.token`), NOT
// the badge key (#key-2, `issuer.publicKey`, which is KMS-backed in prod). This
// regression pins that binding: the route must accept a token signed by the
// token key and reject one signed by the badge key. Verifying against the badge
// key (the original bug) 401s every real userinfo call.

// The route's non-crypto dependencies are mocked so the test isolates the
// signature-key check: rate limiter (always allow), issuer (two distinct keys),
// prisma (a live access-token row), and the claims resolver (no claims).
const getIssuer = vi.fn();
vi.mock("@/lib/issuer", () => ({ getIssuer: () => getIssuer() }));

vi.mock("@/lib/rate-limit", () => ({
  clientIpFrom: () => "test-ip",
  oidcUserinfoLimiter: { check: () => ({ allowed: true, retryAfterSeconds: 0 }) },
}));

const findUnique = vi.fn();
vi.mock("@/lib/prisma", () => ({
  prisma: { oidcAccessToken: { findUnique: (...args: unknown[]) => findUnique(...args) } },
}));

vi.mock("@/lib/oidc-claims", () => ({
  loadApprovedBadgeJwts: () => Promise.resolve([]),
  loadProfileOverride: () => Promise.resolve(null),
  resolveUserClaims: () => ({
    name: undefined,
    picture: undefined,
    sybilBucket: undefined,
    ministerBadges: [],
  }),
}));

import { GET } from "./route";

const ISSUER_URL = "https://issuer.example";

// Distinct keypairs: #key-2 (badge, `issuer.publicKey`) and #key-3 (token,
// `issuer.token`). Held at module scope so the negative control can forge a
// token with the BADGE private key.
let badgePair: { privateKey: KeyLike; publicKey: KeyLike };
let tokenPair: { privateKey: KeyLike; publicKey: KeyLike };
let issuer: Issuer;

const BADGE_KID = "did:web:issuer.example#key-2";
const TOKEN_KID = "did:web:issuer.example#key-3";

async function buildIssuer(): Promise<Issuer> {
  const badgeJwk = (await exportJWK(badgePair.publicKey)) as JWK;
  const tokenJwk = (await exportJWK(tokenPair.publicKey)) as JWK;
  return {
    domain: "issuer.example",
    did: "did:web:issuer.example",
    kid: BADGE_KID,
    signer: {
      sign: () => Promise.reject(new Error("signer.sign unused by mintAccessToken")),
    },
    publicKey: badgePair.publicKey, // #key-2 — the badge/verification key
    publicJwk: badgeJwk,
    token: {
      kid: TOKEN_KID,
      privateKey: tokenPair.privateKey,
      publicKey: tokenPair.publicKey, // #key-3 — signs id/access tokens
      publicJwk: tokenJwk,
    },
  };
}

// Sign an at+jwt with an arbitrary key/kid, mirroring mintAccessToken's claim
// shape. Used to forge a badge-key-signed token for the negative control.
async function signAccessTokenWith(
  key: KeyLike,
  kid: string,
  jti: string,
  sub: string,
): Promise<string> {
  return new SignJWT({ scope: "openid", client_id: "client_A", token_use: "access" })
    .setProtectedHeader({ alg: "EdDSA", kid, typ: "at+jwt" })
    .setIssuer(ISSUER_URL)
    .setSubject(sub)
    .setAudience(ISSUER_URL)
    .setJti(jti)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(key);
}

function liveRow(jti: string, sub: string) {
  return {
    jti,
    revokedAt: null,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    userId: "user_1",
    clientId: "client_A",
    approvedBadgeIds: [] as string[],
    profileName: false,
    profileAvatar: false,
    sybilScore: null,
    sybilBucket: null,
    user: { id: "user_1", displayName: null, avatarUrl: null },
  };
}

function bearer(token: string): Request {
  return new Request(`${ISSUER_URL}/oidc/userinfo`, {
    headers: { authorization: `Bearer ${token}` },
  });
}

describe("GET /oidc/userinfo access-token key binding", () => {
  const ORIGINAL_AUTH_URL = process.env.AUTH_URL;

  beforeAll(async () => {
    process.env.AUTH_URL = ISSUER_URL;
    badgePair = await generateKeyPair("EdDSA");
    tokenPair = await generateKeyPair("EdDSA");
    issuer = await buildIssuer();
  });

  afterAll(() => {
    if (ORIGINAL_AUTH_URL === undefined) delete process.env.AUTH_URL;
    else process.env.AUTH_URL = ORIGINAL_AUTH_URL;
  });

  beforeEach(() => {
    findUnique.mockReset();
    getIssuer.mockReset();
    getIssuer.mockResolvedValue(issuer);
  });

  it("accepts an access token signed with the TOKEN key (#key-3)", async () => {
    const sub = "pairwise_sub_A";
    const token = await mintAccessToken(issuer, {
      jti: "jti_token_key",
      sub,
      clientId: "client_A",
      scopes: ["openid"],
    });
    findUnique.mockResolvedValue(liveRow("jti_token_key", sub));

    const res = await GET(bearer(token));

    // Fails on the old code (verified against issuer.publicKey, the badge key) —
    // the token-key signature never validates, so the route 401s.
    expect(res.status).toBe(200);
    const body = (await res.json()) as { sub?: string };
    expect(body.sub).toBe(sub);
  });

  it("rejects an access token signed with the BADGE key (#key-2)", async () => {
    const sub = "pairwise_sub_B";
    // Forge a token with the BADGE private key — what the old route would have
    // (wrongly) accepted. The fixed route pins to the token key, so this 401s.
    const forged = await signAccessTokenWith(badgePair.privateKey, BADGE_KID, "jti_badge_key", sub);
    findUnique.mockResolvedValue(liveRow("jti_badge_key", sub));

    const res = await GET(bearer(forged));

    expect(res.status).toBe(401);
    const body = (await res.json()) as { error?: string };
    expect(body.error).toBe("invalid_token");
  });
});
