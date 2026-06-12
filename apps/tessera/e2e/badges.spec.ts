import { expect, test } from "@playwright/test";

import { STORAGE, USER_EMAIL } from "./env";
import { ANON_STATE, issueEmailDomainBadge, userIdByEmail } from "./helpers";

test.use({ storageState: STORAGE.user });

test("plugin catalog shows the registered lineup", async ({ page }) => {
  await page.goto("/badges/new");
  for (const name of [
    "Email domain",
    "GitHub",
    "Invite code",
    "TLSNotary attestation",
  ]) {
    await expect(
      page.getByRole("heading", { name, exact: false }),
    ).toBeVisible();
  }
});

test("email-domain wizard issues a badge; public toggle exposes it on /u/[id]", async ({
  page,
  browser,
}) => {
  await issueEmailDomainBadge(page, "proof@example-corp.com");

  await expect(
    page.getByRole("heading", { name: "Email domain" }),
  ).toBeVisible();

  // Private by default: anonymous public profile shows nothing.
  const userId = await userIdByEmail(USER_EMAIL);
  const anon = await browser.newContext({ storageState: ANON_STATE });
  const anonPage = await anon.newPage();
  await anonPage.goto(`/u/${userId}`);
  await expect(
    anonPage.getByRole("heading", { name: "Email domain" }),
  ).toHaveCount(0);

  // Toggle public, then the badge appears for the anonymous viewer.
  await page.goto("/profile");
  await page.getByRole("button", { name: "Make public" }).first().click();
  await expect(
    page.getByRole("button", { name: "Make private" }).first(),
  ).toBeVisible();

  await anonPage.goto(`/u/${userId}`);
  await expect(
    anonPage.getByRole("heading", { name: "Email domain" }),
  ).toBeVisible();
  await anon.close();
});
