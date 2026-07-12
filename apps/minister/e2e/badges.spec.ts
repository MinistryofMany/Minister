import { expect, test } from "@playwright/test";

import { STORAGE, USER_EMAIL } from "./env";
import { ANON_STATE, issueEmailDomainBadge, userIdByEmail } from "./helpers";

test.use({ storageState: STORAGE.user });

test("plugin catalog shows the registered lineup", async ({ page }) => {
  await page.goto("/badges/new");
  // The catalog renders each available plugin's manifest name as a heading.
  // GitHub/Google are OAuth plugins gated by `isConfigured` — hidden unless
  // their client credentials are set, which the e2e server does not provide —
  // so the always-available plugins are the stable lineup to assert on.
  for (const name of ["Email domain", "Invite code", "TLSNotary attestation"]) {
    await expect(page.getByRole("heading", { name, exact: false })).toBeVisible();
  }
});

test("email-domain wizard issues a badge; public toggle exposes it on /u/[id]", async ({
  page,
  browser,
}) => {
  await issueEmailDomainBadge(page, "proof@example-corp.com");

  // Sign-in auto-issues an email-domain badge for the user's OWN domain
  // (e2e.test), so the profile now holds two "Email domain" badges. Scope the
  // assertion to the wizard-issued example-corp.com card specifically.
  const wizardBadge = page
    .locator("div")
    .filter({ has: page.getByRole("heading", { name: "Email domain" }) })
    .filter({ hasText: "example-corp.com" })
    .last();
  await expect(wizardBadge).toBeVisible();

  // Private by default: anonymous public profile shows nothing.
  const userId = await userIdByEmail(USER_EMAIL);
  const anon = await browser.newContext({ storageState: ANON_STATE });
  const anonPage = await anon.newPage();
  await anonPage.goto(`/u/${userId}`);
  await expect(anonPage.getByRole("heading", { name: "Email domain" })).toHaveCount(0);

  // Toggle public, then the badge appears for the anonymous viewer.
  await page.goto("/profile");
  await page.getByRole("button", { name: "Make public" }).first().click();
  await expect(page.getByRole("button", { name: "Make private" }).first()).toBeVisible();

  await anonPage.goto(`/u/${userId}`);
  await expect(anonPage.getByRole("heading", { name: "Email domain" })).toBeVisible();
  await anon.close();
});
