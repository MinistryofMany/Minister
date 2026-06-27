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

// Phase-3 step 2 — end-to-end proof of grant tracking + the locked
// "you've already proven these to this platform" transparency section.
//
// Asserts, against a real /oidc/authorize + /oidc/token round trip:
//   1. Join a room needing {X}: the grant for (user, client) records X.
//   2. Join a room (SAME client) needing {X, Y}: X appears in the locked
//      "already proven" section (auto-checked, disabled), Y is newly
//      selected, and the disclosed set is {X, Y}.
//   3. Join a room (SAME client) that does NOT request a previously-granted
//      type Z: Z is NOT shown in the locked section and NOT disclosed
//      (F-2(a): per-room minimal disclosure holds).
//
// The over-disclosure guard (minimizeToPolicy) remains authoritative — it is
// unit-tested in src/server/oidc-actions.test.ts and exercised end-to-end in
// oidc-policy-selection.spec.ts. Here we additionally prove the grant fold
// never widens disclosure past the room's minimal need.

const REDIRECT_URI = `${BASE_URL}/rp-callback`;

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function encodePolicy(policy: unknown): string {
  return Buffer.from(JSON.stringify(policy), "utf8").toString("base64url");
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

// Drive /oidc/authorize for a "room" expressed as a scope set + optional
// minister_policy. Returns the flow secrets needed for the token exchange.
async function authorize(
  page: Page,
  args: { clientId: string; scope: string; policy?: unknown },
): Promise<{ state: string; nonce: string; verifier: string }> {
  const { verifier, challenge } = pkcePair();
  const state = b64url(randomBytes(16));
  const nonce = b64url(randomBytes(16));
  let url =
    `${BASE_URL}/oidc/authorize?response_type=code&client_id=${encodeURIComponent(args.clientId)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=${encodeURIComponent(args.scope)}` +
    `&state=${state}&nonce=${nonce}` +
    `&code_challenge=${challenge}&code_challenge_method=S256`;
  if (args.policy) url += `&minister_policy=${encodePolicy(args.policy)}`;
  await page.goto(url);
  await expect(page.getByRole("heading", { name: "Approve access" })).toBeVisible();
  return { state, nonce, verifier };
}

// Click approve, follow the redirect back to the RP, return the auth code.
async function approveAndGetCode(page: Page, state: string): Promise<string> {
  await page.getByRole("button", { name: "Approve and continue" }).click();
  await page.waitForURL(/\/rp-callback\?/);
  const cbUrl = new URL(page.url());
  expect(cbUrl.searchParams.get("state")).toBe(state);
  const code = cbUrl.searchParams.get("code");
  if (!code) throw new Error("no auth code in callback");
  return code;
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

test.describe("OIDC grant disclosure + locked already-proven section (Phase 3)", () => {
  test("grant accrues; locked X shown on the next room; Z never leaks (F-2)", async ({
    browser,
    request,
  }) => {
    // One confidential client (one "platform") across all three rooms, so
    // the grant for (user, client) is shared and the transparency section
    // can surface on later authorizes.
    const { clientId, clientSecret } = await createConfidentialOidcClient(REDIRECT_URI, [
      "openid",
      "badge:age-over-18",
      "badge:residency-country",
      "badge:email-domain",
    ]);

    const email = throwawayEmail("grant");
    const ctx = await browser.newContext({ storageState: ANON_STATE });
    const page = await ctx.newPage();
    await signInViaMagicLink(page, email);
    const userId = await prisma.user
      .findUniqueOrThrow({ where: { email }, select: { id: true } })
      .then((u) => u.id);
    // The user holds all three badge kinds.
    await seedBadge(userId, "age-over-18");
    await seedBadge(userId, "residency-country");
    await seedBadge(userId, "email-domain");

    // No grant yet.
    expect(
      await prisma.oidcGrant.findUnique({
        where: { userId_clientId: { userId, clientId } },
      }),
    ).toBeNull();

    // ---- Room A: needs {age-over-18} (single-leaf policy). ----
    {
      const { state, verifier } = await authorize(page, {
        clientId,
        scope: "openid badge:age-over-18",
        policy: { badge: { type: "age-over-18" } },
      });
      // First visit: nothing is locked yet.
      await expect(page.getByText(/already proven these/i)).toHaveCount(0);
      const code = await approveAndGetCode(page, state);
      const badges = await exchangeCode(request, { code, clientId, clientSecret, verifier });
      expect(vcKinds(badges)).toEqual(["age-over-18"]);
    }

    // The grant now records exactly age-over-18.
    const grantAfterA = await prisma.oidcGrant.findUniqueOrThrow({
      where: { userId_clientId: { userId, clientId } },
    });
    expect(grantAfterA.badgeTypes).toEqual(["age-over-18"]);

    // ---- Room B (same client): needs {age-over-18, residency-country}. ----
    {
      const { state, verifier } = await authorize(page, {
        clientId,
        scope: "openid badge:age-over-18 badge:residency-country",
        policy: {
          allOf: [{ badge: { type: "age-over-18" } }, { badge: { type: "residency-country" } }],
        },
      });

      // age-over-18 is shown in the locked "already proven" section,
      // auto-checked and disabled (cannot uncheck).
      await expect(page.getByText(/already proven these/i)).toBeVisible();
      const lockedBox = page.locator('input[data-already-granted="true"]');
      await expect(lockedBox).toHaveCount(1);
      await expect(lockedBox).toBeChecked();
      await expect(lockedBox).toBeDisabled();

      // residency-country is the NEW requirement: it appears in the pickable
      // policy group (its label is the registry name "Country of residence"),
      // pre-selected and NOT locked. age-over-18 is NOT a pickable leaf — it
      // is shown only in the locked section above.
      await expect(page.getByText("Country of residence").first()).toBeVisible();
      const pickable = page.locator(
        'input[type="checkbox"]:checked:not([data-already-granted]):not([id^="scope-profile"]), input[type="radio"]:checked',
      );
      await expect(pickable.first()).toBeVisible();

      const code = await approveAndGetCode(page, state);
      const badges = await exchangeCode(request, { code, clientId, clientSecret, verifier });
      // Disclosure is {age-over-18, residency-country} — the locked X plus
      // the new Y, both because THIS room's minimal set needs both.
      expect(vcKinds(badges).sort()).toEqual(["age-over-18", "residency-country"]);
    }

    // Grant accumulated both types (monotone union).
    const grantAfterB = await prisma.oidcGrant.findUniqueOrThrow({
      where: { userId_clientId: { userId, clientId } },
    });
    expect(grantAfterB.badgeTypes.sort()).toEqual(["age-over-18", "residency-country"]);

    // ---- Room C (same client): needs ONLY {email-domain}. ----
    // age-over-18 and residency-country are granted but this room does not
    // request them → they must NOT show in the locked section and must NOT
    // be disclosed (F-2(a): per-room minimal disclosure).
    {
      const { state, verifier } = await authorize(page, {
        clientId,
        scope: "openid badge:email-domain",
        policy: { badge: { type: "email-domain" } },
      });

      // Nothing locked: the granted types are not requested by this room.
      await expect(page.getByText(/already proven these/i)).toHaveCount(0);
      await expect(page.locator('input[data-already-granted="true"]')).toHaveCount(0);

      const code = await approveAndGetCode(page, state);
      const badges = await exchangeCode(request, { code, clientId, clientSecret, verifier });
      const kinds = vcKinds(badges);
      // ONLY email-domain is disclosed; the previously-granted types
      // never leak into a room that does not request them.
      expect(kinds).toEqual(["email-domain"]);
      expect(kinds).not.toContain("age-over-18");
      expect(kinds).not.toContain("residency-country");
    }

    await ctx.close();
  });
});
