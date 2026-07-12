import { createHash, randomBytes } from "node:crypto";

import { expect, test, type APIRequestContext } from "@playwright/test";

import { BASE_URL } from "./env";
import {
  ANON_STATE,
  createConfidentialOidcClient,
  createPublicOidcClient,
  prisma,
  seedBadge,
  signInViaMagicLink,
  vcKinds,
} from "./helpers";

// Direct exercise of the /oidc/token + /oidc/userinfo security guarantees
// from CLAUDE.md "Required security". Each spec mints a THROWAWAY user
// (the shared `user` storage state accumulates a non-deterministic badge
// set across the suite, which would break the exact-count disclosure
// assertions below) and seeds the authorization-code / access-token rows
// directly so it can target one guarantee at a time.

const REDIRECT_URI = `${BASE_URL}/rp-callback`;

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function pkcePair(): { verifier: string; challenge: string } {
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const part = jwt.split(".")[1];
  if (!part) throw new Error("not a JWT");
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

interface SeedCodeArgs {
  clientId: string;
  userId: string;
  redirectUri?: string;
  scopes: string[];
  approvedBadgeIds?: string[];
  challenge: string;
  codeChallengeMethod?: string;
  expiresAt?: Date;
}

// Insert an OidcAuthorizationCode row exactly as approveConsent would,
// with per-spec overrides for the field under test. Returns the code.
async function seedAuthCode(args: SeedCodeArgs): Promise<string> {
  const code = b64url(randomBytes(32));
  await prisma.oidcAuthorizationCode.create({
    data: {
      code,
      clientId: args.clientId,
      userId: args.userId,
      redirectUri: args.redirectUri ?? REDIRECT_URI,
      scopes: args.scopes,
      approvedBadgeIds: args.approvedBadgeIds ?? [],
      nonce: "n",
      codeChallenge: args.challenge,
      codeChallengeMethod: args.codeChallengeMethod ?? "S256",
      expiresAt: args.expiresAt ?? new Date(Date.now() + 60_000),
    },
  });
  return code;
}

async function newUser(email: string): Promise<string> {
  const u = await prisma.user.create({ data: { email } });
  return u.id;
}

let userSeq = 0;
function throwawayEmail(prefix: string): string {
  return `${prefix}-${++userSeq}-${Math.floor(Date.now() % 1e6)}@e2e.test`;
}

async function postToken(
  request: APIRequestContext,
  form: Record<string, string>,
  headers?: Record<string, string>,
) {
  return request.post(`${BASE_URL}/oidc/token`, { form, headers });
}

// --------------------------------------------------------------------------
// H1 regression — the scope↔badge binding is server-enforced. This is the
// one spec that drives the REAL consent server action, then tampers its
// POST body, because the vulnerability lived in approveConsent.
// --------------------------------------------------------------------------
test("H1: a tampered consent including an unrequested badge discloses only the requested type", async ({
  browser,
}) => {
  const email = throwawayEmail("h1");
  const ctx = await browser.newContext({ storageState: ANON_STATE });
  const page = await ctx.newPage();
  await signInViaMagicLink(page, email);
  const userId = await prisma.user
    .findFirstOrThrow({ where: { email }, select: { id: true } })
    .then((u) => u.id);

  // The RP requests ONLY age-over-21. The user also holds an email-domain
  // badge the RP never asked for.
  const ageBadgeId = await seedBadge(userId, "age-over-21");
  const emailBadgeId = await seedBadge(userId, "email-domain");

  const clientId = await createPublicOidcClient(REDIRECT_URI, ["openid", "badge:age-over-21"]);
  const { verifier, challenge } = pkcePair();
  const state = b64url(randomBytes(16));
  const nonce = b64url(randomBytes(16));
  const authorizeUrl =
    `${BASE_URL}/oidc/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=${encodeURIComponent("openid badge:age-over-21")}` +
    `&state=${state}&nonce=${nonce}` +
    `&code_challenge=${challenge}&code_challenge_method=S256`;

  await page.goto(authorizeUrl);
  await expect(page.getByRole("heading", { name: "Approve access" })).toBeVisible();

  // Tamper the consent server action's body in flight: inject the
  // unrequested email-domain badge id into approvedBadgeIds, simulating a
  // hand-crafted POST. The consent UI never offered this badge.
  // The server action POSTs back to the authorize URL with its full query
  // string, so the glob must allow a trailing query (a bare
  // "**/oidc/authorize" would not match and the tamper would silently
  // no-op, making this spec a tautology).
  await page.route("**/oidc/authorize?**", async (route) => {
    const req = route.request();
    if (req.method() !== "POST") return route.continue();
    const raw = req.postData() ?? "";
    let mutated = raw;
    try {
      const parsed = JSON.parse(raw) as Array<{ approvedBadgeIds?: string[] }>;
      if (Array.isArray(parsed) && parsed[0]) {
        parsed[0].approvedBadgeIds = [...(parsed[0].approvedBadgeIds ?? []), emailBadgeId];
        mutated = JSON.stringify(parsed);
      }
    } catch {
      // Not the JSON action body (e.g. a multipart variant) — pass through.
    }
    return route.continue({ postData: mutated });
  });

  // Tick the (only) offered checkbox — the age-over-21 badge.
  for (const box of await page.getByRole("checkbox").all()) await box.check();
  await page.getByRole("button", { name: "Approve and continue" }).click();
  await page.waitForURL(/\/rp-callback\?/);

  const cbUrl = new URL(page.url());
  const code = cbUrl.searchParams.get("code");
  expect(code).toBeTruthy();
  await ctx.close();

  // Exchange the code. The server must have bound the grant to the
  // requested type only.
  const apiCtx = await browser.newContext();
  const tokenRes = await postToken(apiCtx.request, {
    grant_type: "authorization_code",
    code: code!,
    redirect_uri: REDIRECT_URI,
    client_id: clientId,
    code_verifier: verifier,
  });
  expect(tokenRes.status()).toBe(200);
  const tokens = (await tokenRes.json()) as {
    id_token: string;
    access_token: string;
    scope: string;
  };

  // The granted scope must not include the unrequested badge scope.
  expect(tokens.scope.split(" ")).not.toContain("badge:email-domain");
  expect(tokens.scope.split(" ")).toContain("badge:age-over-21");

  // id_token: exactly the age-over-21 VC, never the email-domain VC.
  const idClaims = decodeJwtPayload(tokens.id_token);
  const idBadges = (idClaims.minister_badges as string[]) ?? [];
  expect(vcKinds(idBadges)).toEqual(["age-over-21"]);

  // userinfo: same guarantee.
  const userinfoRes = await apiCtx.request.get(`${BASE_URL}/oidc/userinfo`, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  expect(userinfoRes.status()).toBe(200);
  const userinfo = (await userinfoRes.json()) as { minister_badges?: string[] };
  expect(vcKinds(userinfo.minister_badges ?? [])).toEqual(["age-over-21"]);

  // And the row the access token resolves through must not carry the
  // unrequested id either — belt and suspenders on the persisted grant.
  const at = await prisma.oidcAccessToken.findFirstOrThrow({ where: { userId } });
  expect(at.approvedBadgeIds).toContain(ageBadgeId);
  expect(at.approvedBadgeIds).not.toContain(emailBadgeId);
  await apiCtx.close();
});

// --------------------------------------------------------------------------
// 2. Authorization-code 60s TTL.
// --------------------------------------------------------------------------
test("expired authorization code is rejected with invalid_grant", async ({ browser }) => {
  const userId = await newUser(throwawayEmail("ttl"));
  const clientId = await createPublicOidcClient(REDIRECT_URI, ["openid"]);
  const { verifier, challenge } = pkcePair();
  const code = await seedAuthCode({
    clientId,
    userId,
    scopes: ["openid"],
    challenge,
    // One second in the past — already past the 60s TTL window.
    expiresAt: new Date(Date.now() - 1000),
  });

  const apiCtx = await browser.newContext();
  const res = await postToken(apiCtx.request, {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    client_id: clientId,
    code_verifier: verifier,
  });
  expect(res.status()).toBe(400);
  expect(((await res.json()) as { error: string }).error).toBe("invalid_grant");
  await apiCtx.close();
});

// --------------------------------------------------------------------------
// 3. Code↔client binding.
// --------------------------------------------------------------------------
test("a code issued for client A cannot be redeemed by client B", async ({ browser }) => {
  const userId = await newUser(throwawayEmail("bind"));
  const clientA = await createPublicOidcClient(REDIRECT_URI, ["openid"]);
  const clientB = await createPublicOidcClient(REDIRECT_URI, ["openid"]);
  const { verifier, challenge } = pkcePair();
  const code = await seedAuthCode({ clientId: clientA, userId, scopes: ["openid"], challenge });

  const apiCtx = await browser.newContext();
  const res = await postToken(apiCtx.request, {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    client_id: clientB,
    code_verifier: verifier,
  });
  expect(res.status()).toBe(400);
  expect(((await res.json()) as { error: string }).error).toBe("invalid_grant");
  await apiCtx.close();
});

// --------------------------------------------------------------------------
// 4. redirect_uri exact-match at /token.
// --------------------------------------------------------------------------
test("redirect_uri mismatch at /token is rejected", async ({ browser }) => {
  const userId = await newUser(throwawayEmail("redir"));
  const clientId = await createPublicOidcClient(REDIRECT_URI, ["openid"]);
  const { verifier, challenge } = pkcePair();
  const code = await seedAuthCode({ clientId, userId, scopes: ["openid"], challenge });

  const apiCtx = await browser.newContext();
  const res = await postToken(apiCtx.request, {
    grant_type: "authorization_code",
    code,
    redirect_uri: `${BASE_URL}/rp-callback-other`,
    client_id: clientId,
    code_verifier: verifier,
  });
  expect(res.status()).toBe(400);
  expect(((await res.json()) as { error: string }).error).toBe("invalid_grant");
  await apiCtx.close();
});

// --------------------------------------------------------------------------
// 5. S256-only — a code stored with a non-S256 method is refused.
// --------------------------------------------------------------------------
test("non-S256 code_challenge_method is rejected at /token", async ({ browser }) => {
  const userId = await newUser(throwawayEmail("s256"));
  const clientId = await createPublicOidcClient(REDIRECT_URI, ["openid"]);
  const { verifier } = pkcePair();
  // "plain" PKCE: challenge == verifier. Even with a correct verifier,
  // /token must refuse anything that isn't S256.
  const code = await seedAuthCode({
    clientId,
    userId,
    scopes: ["openid"],
    challenge: verifier,
    codeChallengeMethod: "plain",
  });

  const apiCtx = await browser.newContext();
  const res = await postToken(apiCtx.request, {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    client_id: clientId,
    code_verifier: verifier,
  });
  expect(res.status()).toBe(400);
  expect(((await res.json()) as { error: string }).error).toBe("invalid_grant");
  await apiCtx.close();
});

// --------------------------------------------------------------------------
// 6. Confidential-client secret enforcement.
// --------------------------------------------------------------------------
test("confidential client: missing or wrong secret yields 401 invalid_client", async ({
  browser,
}) => {
  const userId = await newUser(throwawayEmail("conf"));
  const { clientId, clientSecret } = await createConfidentialOidcClient(REDIRECT_URI, ["openid"]);
  const { verifier, challenge } = pkcePair();

  const apiCtx = await browser.newContext();

  // (a) Missing secret.
  const missingCode = await seedAuthCode({ clientId, userId, scopes: ["openid"], challenge });
  const missing = await postToken(apiCtx.request, {
    grant_type: "authorization_code",
    code: missingCode,
    redirect_uri: REDIRECT_URI,
    client_id: clientId,
    code_verifier: verifier,
  });
  expect(missing.status()).toBe(401);
  expect(((await missing.json()) as { error: string }).error).toBe("invalid_client");

  // (b) Wrong secret.
  const wrongCode = await seedAuthCode({ clientId, userId, scopes: ["openid"], challenge });
  const wrong = await postToken(apiCtx.request, {
    grant_type: "authorization_code",
    code: wrongCode,
    redirect_uri: REDIRECT_URI,
    client_id: clientId,
    client_secret: "not-the-secret",
    code_verifier: verifier,
  });
  expect(wrong.status()).toBe(401);
  expect(((await wrong.json()) as { error: string }).error).toBe("invalid_client");

  // (c) Correct secret still works — proves (a)/(b) failed on auth, not setup.
  const okCode = await seedAuthCode({ clientId, userId, scopes: ["openid"], challenge });
  const ok = await postToken(apiCtx.request, {
    grant_type: "authorization_code",
    code: okCode,
    redirect_uri: REDIRECT_URI,
    client_id: clientId,
    client_secret: clientSecret,
    code_verifier: verifier,
  });
  expect(ok.status()).toBe(200);
  await apiCtx.close();
});

// --------------------------------------------------------------------------
// 7. Ownership filter — a stale approvedBadgeIds carrying another user's
//    badge id never surfaces that badge.
// --------------------------------------------------------------------------
test("another user's badge id in approvedBadgeIds is never disclosed", async ({ browser }) => {
  const victimId = await newUser(throwawayEmail("victim"));
  const grantUserId = await newUser(throwawayEmail("grantee"));
  // The victim holds an email-domain badge.
  const victimBadgeId = await seedBadge(victimId, "email-domain");
  // The grantee holds their own email-domain badge.
  const grantBadgeId = await seedBadge(grantUserId, "email-domain");

  const clientId = await createPublicOidcClient(REDIRECT_URI, ["openid", "badge:email-domain"]);
  const { verifier, challenge } = pkcePair();
  // Code carries BOTH ids; loadApprovedBadgeJwts scopes by userId so the
  // victim's id must be dropped.
  const code = await seedAuthCode({
    clientId,
    userId: grantUserId,
    scopes: ["openid", "badge:email-domain"],
    approvedBadgeIds: [grantBadgeId, victimBadgeId],
    challenge,
  });

  const apiCtx = await browser.newContext();
  const tokenRes = await postToken(apiCtx.request, {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    client_id: clientId,
    code_verifier: verifier,
  });
  expect(tokenRes.status()).toBe(200);
  const tokens = (await tokenRes.json()) as { id_token: string };
  const idClaims = decodeJwtPayload(tokens.id_token);
  const badges = (idClaims.minister_badges as string[]) ?? [];
  // Exactly the grantee's own badge; the victim's is filtered by ownership.
  expect(vcKinds(badges)).toEqual(["email-domain"]);
  const decoded = decodeJwtPayload(badges[0]!) as {
    vc?: { credentialSubject?: { domain?: string } };
  };
  // seedBadge folds the default tag ("email-domain") into the schema-valid
  // domain claim; asserting it proves the grantee's own VC was the one disclosed.
  expect(decoded.vc?.credentialSubject?.domain).toBe("email-domain.example");
  expect(badges.length).toBe(1);
  // Sanity: distinct ids, so "1 VC" really means the victim's was dropped.
  expect(victimBadgeId).not.toBe(grantBadgeId);
  await apiCtx.close();
});

// --------------------------------------------------------------------------
// 9. userinfo negatives.
// --------------------------------------------------------------------------
test("userinfo rejects an id_token presented as a bearer token", async ({ browser }) => {
  // Run a real grant so we have a genuine id_token, then present it where
  // an access token belongs. token_use != "access" → 401.
  const userId = await newUser(throwawayEmail("idtok"));
  const clientId = await createPublicOidcClient(REDIRECT_URI, ["openid", "profile"]);
  const { verifier, challenge } = pkcePair();
  const code = await seedAuthCode({
    clientId,
    userId,
    scopes: ["openid", "profile"],
    challenge,
  });

  const apiCtx = await browser.newContext();
  const tokenRes = await postToken(apiCtx.request, {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    client_id: clientId,
    code_verifier: verifier,
  });
  expect(tokenRes.status()).toBe(200);
  const { id_token } = (await tokenRes.json()) as { id_token: string };

  const res = await apiCtx.request.get(`${BASE_URL}/oidc/userinfo`, {
    headers: { Authorization: `Bearer ${id_token}` },
  });
  expect(res.status()).toBe(401);
  expect(((await res.json()) as { error: string }).error).toBe("invalid_token");
  await apiCtx.close();
});

test("userinfo rejects a revoked or expired access token", async ({ browser }) => {
  const userId = await newUser(throwawayEmail("revoke"));
  const clientId = await createPublicOidcClient(REDIRECT_URI, ["openid", "profile"]);
  const { verifier, challenge } = pkcePair();
  const code = await seedAuthCode({
    clientId,
    userId,
    scopes: ["openid", "profile"],
    challenge,
  });

  const apiCtx = await browser.newContext();
  const tokenRes = await postToken(apiCtx.request, {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    client_id: clientId,
    code_verifier: verifier,
  });
  expect(tokenRes.status()).toBe(200);
  const { access_token } = (await tokenRes.json()) as { access_token: string };
  const jti = decodeJwtPayload(access_token).jti as string;

  // The token works before revocation.
  const before = await apiCtx.request.get(`${BASE_URL}/oidc/userinfo`, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  expect(before.status()).toBe(200);

  // Server-side revoke takes immediate effect, ahead of JWT exp.
  await prisma.oidcAccessToken.update({
    where: { jti },
    data: { revokedAt: new Date() },
  });
  const revoked = await apiCtx.request.get(`${BASE_URL}/oidc/userinfo`, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  expect(revoked.status()).toBe(401);
  expect(((await revoked.json()) as { error: string }).error).toBe("invalid_token");

  // Expiry on the server-side row is likewise enforced beyond JWT exp.
  await prisma.oidcAccessToken.update({
    where: { jti },
    data: { revokedAt: null, expiresAt: new Date(Date.now() - 1000) },
  });
  const expired = await apiCtx.request.get(`${BASE_URL}/oidc/userinfo`, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  expect(expired.status()).toBe(401);
  expect(((await expired.json()) as { error: string }).error).toBe("invalid_token");
  await apiCtx.close();
});

// --------------------------------------------------------------------------
// M2: changing a client revokes its outstanding access tokens. updateOidcClient
// / rotateOidcClientSecret run the admin action's revoke transaction inside a
// $transaction; the admin server action can't be invoked from an API context
// (it gates on an admin session via requireAdmin), so this drives the SAME
// data-layer mutation the action performs — set revokedAt on the client's live
// tokens and drop its codes — and asserts the previously-working access token
// is now refused at /userinfo.
// --------------------------------------------------------------------------
test("changing a client revokes its outstanding access tokens at userinfo", async ({ browser }) => {
  const userId = await newUser(throwawayEmail("clientchg"));
  const { clientId, clientSecret } = await createConfidentialOidcClient(REDIRECT_URI, [
    "openid",
    "profile",
  ]);
  const { verifier, challenge } = pkcePair();
  const code = await seedAuthCode({
    clientId,
    userId,
    scopes: ["openid", "profile"],
    challenge,
  });

  const apiCtx = await browser.newContext();
  const tokenRes = await postToken(apiCtx.request, {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    client_id: clientId,
    client_secret: clientSecret,
    code_verifier: verifier,
  });
  expect(tokenRes.status()).toBe(200);
  const { access_token } = (await tokenRes.json()) as { access_token: string };

  // The token works before the client changes.
  const before = await apiCtx.request.get(`${BASE_URL}/oidc/userinfo`, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  expect(before.status()).toBe(200);

  // Mirror updateOidcClient's transaction: update the client and, in the
  // same transaction, revoke its non-revoked access tokens and drop its
  // outstanding codes (the admin path is keyed by the cuid `id`).
  const dbClient = await prisma.oidcClient.findUniqueOrThrow({
    where: { clientId },
    select: { id: true },
  });
  const [, revoked] = await prisma.$transaction([
    prisma.oidcClient.update({
      where: { id: dbClient.id },
      data: { name: "E2E confidential client (renamed)" },
    }),
    prisma.oidcAccessToken.updateMany({
      where: { clientId, revokedAt: null },
      data: { revokedAt: new Date() },
    }),
    prisma.oidcAuthorizationCode.deleteMany({ where: { clientId } }),
  ]);
  // Sanity: the change actually revoked the live token (not a no-op).
  expect(revoked.count).toBeGreaterThanOrEqual(1);

  // The previously-working token is now refused — userinfo must not keep
  // serving claims under the old client config for the access-token TTL.
  const after = await apiCtx.request.get(`${BASE_URL}/oidc/userinfo`, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  expect(after.status()).toBe(401);
  expect(((await after.json()) as { error: string }).error).toBe("invalid_token");
  await apiCtx.close();
});

// --------------------------------------------------------------------------
// L4: banning a user revokes their outstanding OIDC access tokens. setUserBanned
// bumps sessionGeneration AND, in the same transaction, sets revokedAt on the
// user's live OidcAccessToken rows — closing the ≤1h window where /userinfo
// would keep answering a banned user's token. The admin server action gates on
// an admin session via requireAdmin and can't be invoked from an API context,
// so this drives the SAME data-layer mutation the action performs (keyed by
// userId, not clientId) and asserts the previously-working token is refused.
// --------------------------------------------------------------------------
test("banning a user revokes their outstanding access tokens at userinfo", async ({ browser }) => {
  const userId = await newUser(throwawayEmail("banned"));
  const { clientId, clientSecret } = await createConfidentialOidcClient(REDIRECT_URI, [
    "openid",
    "profile",
  ]);
  const { verifier, challenge } = pkcePair();
  const code = await seedAuthCode({
    clientId,
    userId,
    scopes: ["openid", "profile"],
    challenge,
  });

  const apiCtx = await browser.newContext();
  const tokenRes = await postToken(apiCtx.request, {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    client_id: clientId,
    client_secret: clientSecret,
    code_verifier: verifier,
  });
  expect(tokenRes.status()).toBe(200);
  const { access_token } = (await tokenRes.json()) as { access_token: string };

  // The token works before the ban.
  const before = await apiCtx.request.get(`${BASE_URL}/oidc/userinfo`, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  expect(before.status()).toBe(200);

  // Mirror setUserBanned's transaction: flag the user banned, bump
  // sessionGeneration, and revoke the user's non-revoked access tokens —
  // keyed by userId (the admin path is keyed by the cuid `id`).
  const [, revoked] = await prisma.$transaction([
    prisma.user.update({
      where: { id: userId },
      data: { isBanned: true, sessionGeneration: { increment: 1 } },
    }),
    prisma.oidcAccessToken.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    }),
  ]);
  // Sanity: the ban actually revoked the live token (not a no-op).
  expect(revoked.count).toBeGreaterThanOrEqual(1);

  // The banned user's previously-working token is now refused — userinfo
  // must not keep answering for them under the access-token TTL.
  const after = await apiCtx.request.get(`${BASE_URL}/oidc/userinfo`, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  expect(after.status()).toBe(401);
  expect(((await after.json()) as { error: string }).error).toBe("invalid_token");
  await apiCtx.close();
});

// --------------------------------------------------------------------------
// L1: the WWW-Authenticate header on a 401 carries a fixed, allowlisted
// error_description and never echoes token-derived text (e.g. jose's
// err.message). A malformed bearer token triggers the verify-failure path
// whose JSON body reason must NOT leak into the header.
// --------------------------------------------------------------------------
test("userinfo 401 WWW-Authenticate header is a fixed string, not token-derived", async ({
  browser,
}) => {
  const apiCtx = await browser.newContext();

  // A recognizable, attacker-controlled marker as the bearer token. If any
  // token text reached the header, this substring would appear there.
  const marker = "ZZTOKENMARKERZZ";
  const res = await apiCtx.request.get(`${BASE_URL}/oidc/userinfo`, {
    headers: { Authorization: `Bearer ${marker}.not.a.jwt` },
  });
  expect(res.status()).toBe(401);

  const header = res.headers()["www-authenticate"] ?? "";
  // RFC 6750 grammar + invalid_token code intact.
  expect(header).toContain('error="invalid_token"');
  // Fixed, allowlisted description — exact string, no token-derived text.
  expect(header).toBe(
    'Bearer error="invalid_token", error_description="The access token is invalid or expired"',
  );
  expect(header).not.toContain(marker);
  await apiCtx.close();
});
