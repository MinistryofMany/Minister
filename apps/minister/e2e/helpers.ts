import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, type Page } from "@playwright/test";
import { buildUserDid, issueVc, loadIssuer, type Issuer } from "@minister/vc";

import { hashClientSecret } from "../src/lib/oidc-clients";
import { PrismaClient } from "../src/generated/prisma/index.js";
import { E2E_DATABASE_URL, MAIL_FILE } from "./env";

// One client per worker process; datasourceUrl pins it to the e2e DB
// regardless of what DATABASE_URL the invoking shell carries.
export const prisma = new PrismaClient({ datasourceUrl: E2E_DATABASE_URL });

interface CapturedMail {
  ts: number;
  to: string;
  subject: string;
  text: string;
}

function readMail(): CapturedMail[] {
  let raw: string;
  try {
    raw = readFileSync(MAIL_FILE, "utf8");
  } catch {
    return [];
  }
  return raw
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as CapturedMail);
}

// Poll the capture file for a message to `to` newer than `since`.
export async function waitForMailTo(
  to: string,
  since: number,
  timeoutMs = 15_000,
): Promise<CapturedMail> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const match = readMail()
      .filter((m) => m.to === to && m.ts >= since)
      .at(-1);
    if (match) return match;
    if (Date.now() > deadline) {
      throw new Error(`No captured mail to ${to} within ${timeoutMs}ms`);
    }
    await new Promise((r) => setTimeout(r, 200));
  }
}

export function extractUrl(text: string, pathFragment: string): string {
  const match = text.split(/\s+/).find((w) => w.startsWith("http") && w.includes(pathFragment));
  if (!match) {
    throw new Error(`No URL containing "${pathFragment}" in: ${text}`);
  }
  return match;
}

// Drive the sign-in form and return the magic-link URL from the mail
// capture without visiting it.
//
// The click is retried: in dev mode the first visit can win the race
// against hydration, in which case the button renders but the handler
// isn't attached yet and the click is a no-op.
export async function requestMagicLink(page: Page, email: string): Promise<string> {
  let mail: CapturedMail | null = null;
  for (let attempt = 0; attempt < 3 && !mail; attempt++) {
    // Fresh navigation each attempt — a successful click moves the page
    // to Auth.js's verify-request screen, where the form no longer
    // exists.
    await page.goto("/");
    const since = Date.now();
    await page.getByPlaceholder("you@example.com").fill(email);
    await page.getByRole("button", { name: "Email me a magic link" }).click();
    mail = await waitForMailTo(email, since, 8000).catch(() => null);
  }
  if (!mail) {
    throw new Error(`Sign-in click never produced a magic link for ${email}`);
  }
  return extractUrl(mail.text, "/api/auth/callback/email");
}

// Full magic-link sign-in through the real UI + capture file. Ends on
// /profile (Auth.js default callback for our sign-in form).
export async function signInViaMagicLink(page: Page, email: string): Promise<void> {
  const url = await requestMagicLink(page, email);
  await page.goto(url);
  await expect(page.getByRole("link", { name: "Profile" })).toBeVisible();
}

export async function signOut(page: Page): Promise<void> {
  await page.goto("/settings");
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page.getByRole("button", { name: "Email me a magic link" })).toBeVisible();
}

// Drives the email-domain wizard end-to-end for whatever user the page
// is signed in as. `proofEmail`'s domain becomes the badge claim.
export async function issueEmailDomainBadge(page: Page, proofEmail: string): Promise<void> {
  const since = Date.now();
  await page.goto("/badges/new/email-domain");
  await page.locator('input[type="email"]').fill(proofEmail);
  await page.getByRole("button", { name: "Send verification link" }).click();
  const mail = await waitForMailTo(proofEmail, since);
  const url = extractUrl(mail.text, "/badges/new/email-domain/verify");
  await page.goto(url);
  await expect(page).toHaveURL(/\/profile\?issued=email-domain/);
}

export async function userIdByEmail(email: string): Promise<string> {
  // email is no longer @unique on User (multi-credential identity); resolve
  // against the denormalized primary-email cache. Tests seed one user per
  // throwaway address so findFirst is unambiguous.
  const user = await prisma.user.findFirst({
    where: { email },
    select: { id: true },
  });
  if (!user) throw new Error(`No user with email ${email}`);
  return user.id;
}

export async function grantAdmin(email: string): Promise<void> {
  await prisma.user.updateMany({ where: { email }, data: { isAdmin: true } });
}

// Insert a public (PKCE-only, no secret) OIDC client directly. Enough for
// the authorize-request validation paths, which never reach token exchange.
let oidcClientSeq = 0;
export async function createPublicOidcClient(
  redirectUri: string,
  scopes: string[],
): Promise<string> {
  const clientId = `mc_e2e_${++oidcClientSeq}_${Math.floor(Date.now() % 1e6)}`;
  await prisma.oidcClient.create({
    data: {
      clientId,
      clientSecretHash: null,
      name: "E2E client",
      redirectUris: [redirectUri],
      allowedScopes: scopes,
    },
  });
  return clientId;
}

// Insert a confidential OIDC client (Argon2id-hashed secret) directly,
// returning both ids. Used by /token security specs that exercise client
// authentication without driving the admin registration UI.
export async function createConfidentialOidcClient(
  redirectUri: string,
  scopes: string[],
): Promise<{ clientId: string; clientSecret: string }> {
  const clientId = `mc_e2e_${++oidcClientSeq}_${Math.floor(Date.now() % 1e6)}`;
  const clientSecret = randomBytes(24).toString("base64url");
  await prisma.oidcClient.create({
    data: {
      clientId,
      clientSecretHash: await hashClientSecret(clientSecret),
      name: "E2E confidential client",
      redirectUris: [redirectUri],
      allowedScopes: scopes,
    },
  });
  return { clientId, clientSecret };
}

// Load the same issuer key the e2e dev server uses (the persisted dev key
// under apps/minister/dev-keys). Seeded badge VCs must be REAL signed,
// expiring VCs because the OIDC disclosure path now re-mints each stored VC
// under a pairwise subject (it decodes the stored VC, swaps the subject, and
// re-signs, preserving exp/jti/claims). A fake unsigned VC with no exp would
// be rejected at re-mint.
const HELPERS_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEV_KEY_PATH = path.join(HELPERS_DIR, "..", "dev-keys", "issuer.jwk");
let issuerPromise: Promise<Issuer> | undefined;
function e2eIssuer(): Promise<Issuer> {
  if (!issuerPromise) {
    issuerPromise = loadIssuer({ domain: "minister.local", devKeyPath: DEV_KEY_PATH });
  }
  return issuerPromise;
}

// Seed a Badge row with a real, signed JWT-VC. The stored VC carries the
// global holder DID (as real issuance does); a `kind`/`tag` claim lets a
// spec assert exactly which credential was disclosed (the re-mint preserves
// all claims). `tag` makes the embedded value unique per badge so duplicate
// types stay distinguishable.
export async function seedBadge(userId: string, type: string, tag = type): Promise<string> {
  const issuer = await e2eIssuer();
  const badge = await prisma.badge.create({
    data: {
      userId,
      type,
      attributes: { tag },
      vcJwt: "",
      issuer: issuer.did,
    },
  });
  const vcJwt = await issueVc(
    issuer,
    type,
    buildUserDid(issuer.domain, userId),
    { kind: type, tag },
    { jti: badge.id, expiresIn: "1y" },
  );
  await prisma.badge.update({ where: { id: badge.id }, data: { vcJwt } });
  return badge.id;
}

// Resolve which credential kinds a list of emitted VC JWTs carry. Pairs
// with seedBadge's payload shape.
export function vcKinds(vcJwts: string[]): string[] {
  return vcJwts.map((jwt) => {
    const part = jwt.split(".")[1];
    if (!part) throw new Error("not a JWT");
    const decoded = JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as {
      vc?: { credentialSubject?: { kind?: string } };
    };
    const kind = decoded.vc?.credentialSubject?.kind;
    if (typeof kind !== "string") throw new Error("VC missing credentialSubject.kind");
    return kind;
  });
}

// Accept every native confirm() the page raises from here on.
export function acceptDialogs(page: Page): void {
  page.on("dialog", (dialog) => void dialog.accept());
}

// @playwright/test applies test.use({ storageState }) to
// browser.newContext() as well — pass this to get a genuinely
// anonymous context inside a spec that uses a signed-in default.
export const ANON_STATE = { cookies: [], origins: [] };
