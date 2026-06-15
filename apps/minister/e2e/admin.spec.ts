import { expect, test } from "@playwright/test";

import { STORAGE } from "./env";
import { ANON_STATE, acceptDialogs, signInViaMagicLink } from "./helpers";

test.use({ storageState: STORAGE.admin });

test("ban locks the user out immediately; unban restores access", async ({ page, browser }) => {
  // Mint a dedicated victim with a live session.
  const victim = await browser.newContext({ storageState: ANON_STATE });
  const victimPage = await victim.newPage();
  await signInViaMagicLink(victimPage, "banme@e2e.test");
  await victimPage.goto("/profile");
  await expect(victimPage.getByRole("heading", { name: "Profile" })).toBeVisible();

  acceptDialogs(page);
  await page.goto("/admin/users");
  const victimRow = page.locator("li", { hasText: "banme@e2e.test" });
  await victimRow.getByRole("button", { name: "Ban", exact: true }).click();
  await expect(victimRow.getByText("banned")).toBeVisible();

  // The victim's existing JWT no longer counts as signed in.
  await victimPage.goto("/profile");
  await expect(victimPage).toHaveURL(/\/(\?from=.*)?$/);
  await expect(victimPage.getByRole("button", { name: "Email me a magic link" })).toBeVisible();

  await victimRow.getByRole("button", { name: "Unban" }).click();
  await expect(victimRow.getByText("banned")).toHaveCount(0);
  await victim.close();
});

test("promote and demote from the Users tab; self-row has no buttons", async ({ page }) => {
  acceptDialogs(page);
  await page.goto("/admin/users");

  // Self-guard: the admin's own row exposes no role/ban controls.
  const selfRow = page.locator("li", { hasText: "admin@e2e.test" });
  await expect(selfRow.getByRole("button")).toHaveCount(0);

  const row = page.locator("li", { hasText: "banme@e2e.test" });
  await row.getByRole("button", { name: "Make admin" }).click();
  await expect(row.getByText("admin", { exact: true })).toBeVisible();

  await row.getByRole("button", { name: "Demote" }).click();
  await expect(row.getByText("admin", { exact: true })).toHaveCount(0);
});

test("OIDC client lifecycle: register public client, delete it", async ({ page }) => {
  acceptDialogs(page);
  await page.goto("/admin/oidc-clients");
  await page.getByPlaceholder("Their app").fill("E2E throwaway");
  await page.getByPlaceholder(/theirapp\.com/).fill("https://e2e.example.com/callback");
  await page.getByRole("checkbox", { name: "Public client", exact: false }).check();
  await page.getByRole("button", { name: "Register client" }).click();

  await expect(page.getByText("Public client — no secret")).toBeVisible();
  const clientId = await page.locator("input[readonly]").first().inputValue();
  expect(clientId).toMatch(/^tc_/);

  const row = page.locator("li", { hasText: "E2E throwaway" });
  await expect(row.getByText("public · PKCE-only")).toBeVisible();
  await row.getByRole("button", { name: "Delete" }).click();
  await expect(page.locator("li", { hasText: "E2E throwaway" })).toHaveCount(0);
});

test("non-admins can't reach /admin", async ({ browser }) => {
  const user = await browser.newContext({ storageState: STORAGE.user });
  const userPage = await user.newPage();
  await userPage.goto("/admin/users");
  // /admin redirects non-admins to /, and / forwards signed-in users
  // on to /profile — either way, no admin surface.
  await expect(userPage).not.toHaveURL(/\/admin/);
  await expect(userPage.getByRole("heading", { name: "Admin" })).toHaveCount(0);
  await user.close();
});
