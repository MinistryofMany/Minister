import { expect, test, type Page } from "@playwright/test";

import { STORAGE } from "./env";
import {
  acceptDialogs,
  completeSetup,
  extractUrl,
  signInViaMagicLink,
  waitForMailTo,
} from "./helpers";

// Phase 5 email model, end-to-end through the real UI + magic-link capture:
//   - the email-domain and email-exact badges both issue for one address, with
//     distinct dedup namespaces (no self-collision);
//   - the SAME normalized address on a second account is refused `taken`;
//   - deleting the first account's badge RELEASES the anchor, letting the second
//     account then verify (release → re-verify).

// Drive an email wizard (email-domain | email-exact) to its verify page and
// report the outcome. On success the verify page redirects to
// /profile?issued=...; on a `taken` refusal it renders the outcome shell text.
async function runEmailWizard(
  page: Page,
  pluginId: "email-domain" | "email-exact",
  proofEmail: string,
): Promise<{ issued: boolean; errorText: string }> {
  const since = Date.now();
  await page.goto(`/badges/new/${pluginId}`);
  await page.locator('input[type="email"]').fill(proofEmail);
  await page.getByRole("button", { name: "Send verification link" }).click();
  const mail = await waitForMailTo(proofEmail, since);
  const url = extractUrl(mail.text, `/badges/new/${pluginId}/verify`);
  await page.goto(url);

  if (/\/profile\?issued=/.test(page.url())) {
    return { issued: true, errorText: "" };
  }
  const errorText = (await page.locator("body").innerText()).trim();
  return { issued: false, errorText };
}

test.describe("email badges — issuance", () => {
  test.use({ storageState: STORAGE.user });

  test("email-domain + email-exact both issue for one address (distinct namespaces)", async ({
    page,
  }) => {
    const addr = "founder@both-badges.example";

    expect((await runEmailWizard(page, "email-domain", addr)).issued).toBe(true);
    // Same mailbox, DIFFERENT badge_type ⇒ NOT refused as taken.
    expect((await runEmailWizard(page, "email-exact", addr)).issued).toBe(true);

    // Both badges are the real proof (each wizard redirected to
    // /profile?issued=…). On the profile, assert the specific claims: the
    // email-exact card reveals the full address; an Email-domain card carries
    // the domain (there may be more than one email-domain badge, e.g. the
    // sign-in auto-issued one, so scope to this address's domain).
    await page.goto("/profile");
    await expect(page.getByText("founder@both-badges.example")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Email address" })).toBeVisible();
    await expect(page.getByText("both-badges.example").first()).toBeVisible();
  });
});

test.describe("email badges — cross-account dedup + release", () => {
  test("same address is refused on a second account; deleting the first releases it", async ({
    browser,
  }) => {
    const addr = "shared@release-probe.example";

    // Freemail logins (gmail) so the sign-in auto-issue path is SKIPPED — each
    // account then holds EXACTLY the badges it verifies, making the anchor and
    // the delete target unambiguous.
    const ctxA = await browser.newContext();
    const pageA = await ctxA.newPage();
    acceptDialogs(pageA);
    await signInViaMagicLink(pageA, "release-a@gmail.com");
    // Skip the forced /welcome onboarding so the gated /badges wizard renders.
    await completeSetup("release-a@gmail.com");
    expect((await runEmailWizard(pageA, "email-domain", addr)).issued).toBe(true);

    const ctxB = await browser.newContext();
    const pageB = await ctxB.newPage();
    await signInViaMagicLink(pageB, "release-b@gmail.com");
    // Skip the forced /welcome onboarding so the gated /badges wizard renders.
    await completeSetup("release-b@gmail.com");

    // Second account, same address → refused with the EMAIL-worded copy.
    const refused = await runEmailWizard(pageB, "email-domain", addr);
    expect(refused.issued).toBe(false);
    expect(refused.errorText).toContain("already linked to another Minister account");
    expect(refused.errorText).toContain("email address");

    // Account A deletes its only badge → releases the anchor.
    await pageA.goto("/profile");
    await expect(page_heading(pageA)).toBeVisible();
    await pageA.getByRole("button", { name: "Delete badge" }).click();
    await expect(pageA.getByRole("heading", { name: "Email domain" })).toHaveCount(0, {
      timeout: 10_000,
    });

    // Account B retries → now succeeds (the credential was freed).
    expect((await runEmailWizard(pageB, "email-domain", addr)).issued).toBe(true);

    await ctxA.close();
    await ctxB.close();
  });
});

function page_heading(page: Page) {
  return page.getByRole("heading", { name: "Email domain" });
}
