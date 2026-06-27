import { createHash, randomBytes } from "node:crypto";

import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

import { BASE_URL } from "./env";
import {
  ANON_STATE,
  createConfidentialOidcClient,
  prisma,
  seedBadge,
  signInViaMagicLink,
  vcKinds,
} from "./helpers";

// M6 — end-to-end proof of the Phase-2 anonymity-aware OR selection +
// over-disclosure invariant. Drives a real /oidc/authorize with a
// minister_policy param as a relying party, then exchanges the code and
// inspects the minted minister_badges. Asserts:
//   - anyOf pre-selects + discloses exactly ONE branch (the most anonymous)
//   - overriding the radio discloses a DIFFERENT single branch
//   - a user holding neither branch discloses nothing satisfying
//
// The over-disclosure invariant (F-5) is that minister_badges never carries
// more than one satisfying branch — proven here end-to-end, and at the unit
// level in src/server/oidc-actions.test.ts.

const REDIRECT_URI = `${BASE_URL}/rp-callback`;

// The OR policy under test: satisfy age-over-18 OR residency-country.
const POLICY = {
  anyOf: [{ badge: { type: "age-over-18" } }, { badge: { type: "residency-country" } }],
};
const POLICY_PARAM = Buffer.from(JSON.stringify(POLICY), "utf8").toString("base64url");
const POLICY_SCOPE = "openid badge:age-over-18 badge:residency-country";

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

let userSeq = 0;
function throwawayEmail(prefix: string): string {
  return `${prefix}-${++userSeq}-${Math.floor(Date.now() % 1e6)}@e2e.test`;
}

// Make age-over-18 the strictly more-anonymous branch by giving it more
// distinct holders than residency-country. Seeded once, before any
// authorize call populates the 60s holder-count cache.
async function padAnonymitySets(): Promise<void> {
  for (let i = 0; i < 20; i++) {
    const u = await prisma.user.create({ data: { email: throwawayEmail("pad-age") } });
    await seedBadge(u.id, "age-over-18");
  }
  for (let i = 0; i < 3; i++) {
    const u = await prisma.user.create({ data: { email: throwawayEmail("pad-resid") } });
    await seedBadge(u.id, "residency-country");
  }
}

async function authorizeWithPolicy(
  page: Page,
  clientId: string,
): Promise<{ state: string; nonce: string; verifier: string }> {
  const { verifier, challenge } = pkcePair();
  const state = b64url(randomBytes(16));
  const nonce = b64url(randomBytes(16));
  const url =
    `${BASE_URL}/oidc/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=${encodeURIComponent(POLICY_SCOPE)}` +
    `&state=${state}&nonce=${nonce}` +
    `&code_challenge=${challenge}&code_challenge_method=S256` +
    `&minister_policy=${POLICY_PARAM}`;
  await page.goto(url);
  await expect(page.getByRole("heading", { name: "Approve access" })).toBeVisible();
  return { state, nonce, verifier };
}

async function exchangeCode(
  request: APIRequestContext,
  args: { code: string; clientId: string; clientSecret: string; verifier: string },
): Promise<string[]> {
  const res = await request.post(`${BASE_URL}/oidc/token`, {
    form: {
      grant_type: "authorization_code",
      code: args.code,
      redirect_uri: REDIRECT_URI,
      client_id: args.clientId,
      client_secret: args.clientSecret,
      code_verifier: args.verifier,
    },
  });
  expect(res.status()).toBe(200);
  const tokens = (await res.json()) as { id_token: string };
  const claims = decodeJwtPayload(tokens.id_token);
  return (claims.minister_badges as string[]) ?? [];
}

test.describe("OIDC policy selection (Phase 2)", () => {
  test.beforeAll(async () => {
    await padAnonymitySets();
  });

  test("anyOf: pre-selects + discloses exactly the most-anonymous branch", async ({
    browser,
    request,
  }) => {
    const { clientId, clientSecret } = await createConfidentialOidcClient(REDIRECT_URI, [
      "openid",
      "badge:age-over-18",
      "badge:residency-country",
    ]);

    const email = throwawayEmail("orsel");
    const ctx = await browser.newContext({ storageState: ANON_STATE });
    const page = await ctx.newPage();
    await signInViaMagicLink(page, email);
    const userId = await prisma.user
      .findUniqueOrThrow({ where: { email }, select: { id: true } })
      .then((u) => u.id);
    await seedBadge(userId, "age-over-18");
    await seedBadge(userId, "residency-country");

    const { state, verifier } = await authorizeWithPolicy(page, clientId);

    // The most-anonymous branch (age-over-18) radio is pre-selected.
    const ageRadio = page.locator('input[type="radio"]').first();
    await expect(ageRadio).toBeChecked();

    await page.getByRole("button", { name: "Approve and continue" }).click();
    await page.waitForURL(/\/rp-callback\?/);
    const cbUrl = new URL(page.url());
    expect(cbUrl.searchParams.get("state")).toBe(state);
    const code = cbUrl.searchParams.get("code")!;

    const badges = await exchangeCode(request, { code, clientId, clientSecret, verifier });
    const kinds = vcKinds(badges);
    // Exactly one satisfying branch disclosed — the most anonymous.
    expect(kinds).toEqual(["age-over-18"]);

    await ctx.close();
  });

  test("override: switching the radio discloses a different single branch", async ({
    browser,
    request,
  }) => {
    const { clientId, clientSecret } = await createConfidentialOidcClient(REDIRECT_URI, [
      "openid",
      "badge:age-over-18",
      "badge:residency-country",
    ]);

    const email = throwawayEmail("orsel-override");
    const ctx = await browser.newContext({ storageState: ANON_STATE });
    const page = await ctx.newPage();
    await signInViaMagicLink(page, email);
    const userId = await prisma.user
      .findUniqueOrThrow({ where: { email }, select: { id: true } })
      .then((u) => u.id);
    await seedBadge(userId, "age-over-18");
    await seedBadge(userId, "residency-country");

    const { state, verifier } = await authorizeWithPolicy(page, clientId);

    // Override: pick the residency-country radio instead of the pre-selected
    // age-over-18. Radios are mutually exclusive, so this clears the default.
    const radios = page.locator('input[type="radio"]');
    await radios.nth(1).check();
    await expect(radios.nth(0)).not.toBeChecked();

    await page.getByRole("button", { name: "Approve and continue" }).click();
    await page.waitForURL(/\/rp-callback\?/);
    const cbUrl = new URL(page.url());
    expect(cbUrl.searchParams.get("state")).toBe(state);
    const code = cbUrl.searchParams.get("code")!;

    const badges = await exchangeCode(request, { code, clientId, clientSecret, verifier });
    expect(vcKinds(badges)).toEqual(["residency-country"]);

    await ctx.close();
  });

  test("holds none: user satisfying no branch discloses nothing", async ({ browser, request }) => {
    const { clientId, clientSecret } = await createConfidentialOidcClient(REDIRECT_URI, [
      "openid",
      "badge:age-over-18",
      "badge:residency-country",
    ]);

    const email = throwawayEmail("orsel-none");
    const ctx = await browser.newContext({ storageState: ANON_STATE });
    const page = await ctx.newPage();
    await signInViaMagicLink(page, email);
    // No age-over-18 / residency-country badge for this user.

    const { state, verifier } = await authorizeWithPolicy(page, clientId);

    // Nothing is pre-selected (no satisfying holding); the unmet hint shows.
    await expect(page.getByText(/don't hold a badge that satisfies/i)).toBeVisible();
    await page.getByRole("button", { name: "Approve and continue" }).click();
    await page.waitForURL(/\/rp-callback\?/);
    const cbUrl = new URL(page.url());
    expect(cbUrl.searchParams.get("state")).toBe(state);
    const code = cbUrl.searchParams.get("code")!;

    const badges = await exchangeCode(request, { code, clientId, clientSecret, verifier });
    // No satisfying branch ⇒ nothing disclosed.
    expect(badges).toEqual([]);

    await ctx.close();
  });
});
