import { expect, test } from "@playwright/test";

import { requestMagicLink, signInViaMagicLink, signOut } from "./helpers";

// Fresh-context spec: no storage state on purpose — sign-in IS the
// thing under test here.

test("middleware bounces anonymous visitors off protected routes", async ({
  page,
}) => {
  await page.goto("/profile");
  await expect(page).toHaveURL(/\/\?from=%2Fprofile/);
  await expect(
    page.getByRole("button", { name: "Email me a magic link" }),
  ).toBeVisible();
});

test("magic-link sign-in lands on /profile; sign-out reverts the nav", async ({
  page,
}) => {
  await signInViaMagicLink(page, "fresh@e2e.test");
  await page.goto("/profile");
  await expect(
    page.getByRole("heading", { name: "Profile" }),
  ).toBeVisible();

  await signOut(page);
  await page.goto("/profile");
  await expect(page).toHaveURL(/\/\?from=%2Fprofile/);
});

test("a magic link can't be redeemed twice", async ({ page, browser }) => {
  const url = await requestMagicLink(page, "once@e2e.test");

  // First redemption: signs in.
  await page.goto(url);
  await expect(page.getByRole("link", { name: "Profile" })).toBeVisible();

  // Replay in a pristine context — the forwarded-email scenario. The
  // verification token was consumed, so the same URL must yield the
  // Auth.js Verification error and no session.
  const thief = await browser.newContext();
  const thiefPage = await thief.newPage();
  await thiefPage.goto(url);
  await expect(thiefPage).toHaveURL(/error=Verification/);
  await thiefPage.goto("/profile");
  await expect(thiefPage).toHaveURL(/\/\?from=%2Fprofile/);
  await thief.close();
});
