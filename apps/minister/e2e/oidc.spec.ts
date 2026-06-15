import { createHash, randomBytes } from "node:crypto";

import { expect, test, type APIRequestContext } from "@playwright/test";

import { BASE_URL, STORAGE } from "./env";
import { issueEmailDomainBadge } from "./helpers";

// Full authorization-code + PKCE dance against the provider, with the
// test itself playing the relying party — no demo-client involved.
// The redirect URI 404s on our own app; only its query string matters.

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

async function exchangeCode(
  request: APIRequestContext,
  args: {
    code: string;
    clientId: string;
    clientSecret: string;
    verifier: string;
  },
) {
  return request.post(`${BASE_URL}/oidc/token`, {
    form: {
      grant_type: "authorization_code",
      code: args.code,
      redirect_uri: REDIRECT_URI,
      client_id: args.clientId,
      client_secret: args.clientSecret,
      code_verifier: args.verifier,
    },
  });
}

test("authorization-code + PKCE dance end-to-end", async ({ browser, request }) => {
  // Register the RP through the admin UI; capture the one-time secret.
  const admin = await browser.newContext({ storageState: STORAGE.admin });
  const adminPage = await admin.newPage();
  await adminPage.goto("/admin/oidc-clients");
  await adminPage.getByPlaceholder("Their app").fill("E2E relying party");
  await adminPage.getByPlaceholder(/theirapp\.com/).fill(REDIRECT_URI);
  await adminPage.getByRole("checkbox", { name: "badge:email-domain" }).check();
  await adminPage.getByRole("button", { name: "Register client" }).click();
  await expect(adminPage.getByText("Client registered")).toBeVisible();
  const readonlies = adminPage.locator("input[readonly]");
  const clientId = await readonlies.nth(0).inputValue();
  const clientSecret = await readonlies.nth(1).inputValue();
  expect(clientId).toMatch(/^tc_/);
  expect(clientSecret.length).toBeGreaterThan(20);
  await admin.close();

  // The user needs a disclosable badge.
  const user = await browser.newContext({ storageState: STORAGE.user });
  const page = await user.newPage();
  await issueEmailDomainBadge(page, "oidc-proof@example-corp.com");

  // Authorize → consent → approve → code lands on the redirect URI.
  const { verifier, challenge } = pkcePair();
  const state = b64url(randomBytes(16));
  const nonce = b64url(randomBytes(16));
  const authorizeUrl =
    `${BASE_URL}/oidc/authorize?response_type=code` +
    `&client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=${encodeURIComponent("openid profile badge:email-domain")}` +
    `&state=${state}&nonce=${nonce}` +
    `&code_challenge=${challenge}&code_challenge_method=S256`;

  await page.goto(authorizeUrl);
  await expect(page.getByRole("heading", { name: "Approve access" })).toBeVisible();
  for (const box of await page.getByRole("checkbox").all()) {
    await box.check();
  }
  await page.getByRole("button", { name: "Approve and continue" }).click();
  await page.waitForURL(/\/rp-callback\?/);

  const cbUrl = new URL(page.url());
  expect(cbUrl.searchParams.get("state")).toBe(state);
  const code = cbUrl.searchParams.get("code");
  expect(code).toBeTruthy();

  // Code → tokens.
  const tokenRes = await exchangeCode(request, {
    code: code!,
    clientId,
    clientSecret,
    verifier,
  });
  expect(tokenRes.status()).toBe(200);
  const tokens = (await tokenRes.json()) as {
    id_token: string;
    access_token: string;
    token_type: string;
  };
  expect(tokens.token_type.toLowerCase()).toBe("bearer");

  const idClaims = decodeJwtPayload(tokens.id_token);
  expect(idClaims.iss).toBe(BASE_URL);
  expect(idClaims.aud).toBe(clientId);
  expect(idClaims.nonce).toBe(nonce);
  expect(typeof idClaims.sub).toBe("string");
  // The user may hold several email-domain badges by this point in the
  // suite (earlier specs mint their own) — what matters is that every
  // approved badge arrives as a VC bound to the user's DID.
  const badges = idClaims.minister_badges as string[];
  expect(Array.isArray(badges)).toBe(true);
  expect(badges.length).toBeGreaterThanOrEqual(1);
  for (const vc of badges) {
    const vcClaims = decodeJwtPayload(vc);
    expect(String(vcClaims.sub)).toContain("did:web:minister.local:users:");
  }

  // The access token carries no raw user id — userinfo resolves it.
  const accessClaims = decodeJwtPayload(tokens.access_token);
  expect(accessClaims.minister_uid).toBeUndefined();

  const userinfoRes = await request.get(`${BASE_URL}/oidc/userinfo`, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  expect(userinfoRes.status()).toBe(200);
  const userinfo = (await userinfoRes.json()) as Record<string, unknown>;
  expect(userinfo.sub).toBe(idClaims.sub);

  // Replay protection: the same code must not exchange twice.
  const replay = await exchangeCode(request, {
    code: code!,
    clientId,
    clientSecret,
    verifier,
  });
  expect(replay.status()).toBeGreaterThanOrEqual(400);
  const replayBody = (await replay.json()) as { error: string };
  expect(replayBody.error).toBe("invalid_grant");

  await user.close();
});
