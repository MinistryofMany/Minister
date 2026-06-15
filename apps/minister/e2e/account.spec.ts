import { expect, test } from "@playwright/test";

import { ANON_STATE, acceptDialogs, issueEmailDomainBadge, signInViaMagicLink } from "./helpers";

// Each test manages its own context. The sign-out-all test mints a
// throwaway user so revoking sessions never touches the shared fixtures.

test("'sign out of all devices' revokes the current session", async ({ browser }) => {
  const ctx = await browser.newContext({ storageState: ANON_STATE });
  const page = await ctx.newPage();
  await signInViaMagicLink(page, "signoutall@e2e.test");

  acceptDialogs(page);
  await page.goto("/settings");
  await page.getByRole("button", { name: /Sign out of all devices/i }).click();

  // The current device's JWT is now stale (gen bumped) — protected pages
  // no longer render; /profile bounces to the signed-out home.
  await expect(async () => {
    await page.goto("/profile");
    await expect(page.getByRole("button", { name: "Email me a magic link" })).toBeVisible({
      timeout: 2000,
    });
  }).toPass();
  await ctx.close();
});

test("an account-gated share link blocks anonymous viewers", async ({ browser }) => {
  // Own throwaway user so issuing a badge doesn't perturb shared fixtures.
  const owner = await browser.newContext({ storageState: ANON_STATE });
  const ownerPage = await owner.newPage();
  await signInViaMagicLink(ownerPage, "gateowner@e2e.test");
  await issueEmailDomainBadge(ownerPage, "gate-proof@example-corp.com");

  await ownerPage.goto("/shares");
  await ownerPage.locator('input[type="checkbox"]').first().check(); // a badge
  await ownerPage.getByText("Require a Minister account").click(); // the gate
  await ownerPage.getByRole("button", { name: "Create share link" }).click();
  const url = await ownerPage.locator("input[readonly]").first().inputValue();
  expect(url).toMatch(/\/share\/[A-Za-z0-9_-]{43}$/);

  const anon = await browser.newContext({ storageState: ANON_STATE });
  const anonPage = await anon.newPage();
  await anonPage.goto(url);
  await expect(anonPage.getByRole("heading", { name: "Sign-in required" })).toBeVisible();
  // The shared badge must NOT render for the gated anonymous viewer.
  await expect(anonPage.getByRole("heading", { name: "Email domain" })).toHaveCount(0);

  await owner.close();
  await anon.close();
});
