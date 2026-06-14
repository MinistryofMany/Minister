import { expect, test, type Browser, type Page } from "@playwright/test";

import { STORAGE } from "./env";

async function pageWith(browser: Browser, storageState: string): Promise<Page> {
  const context = await browser.newContext({ storageState });
  return context.newPage();
}

test("invite code: mint as admin, redeem lowercase, exhaust, reject", async ({
  browser,
}) => {
  // Admin mints a single-use code through the UI.
  const admin = await pageWith(browser, STORAGE.admin);
  await admin.goto("/admin/invite-codes");
  await admin.getByPlaceholder("Beta cohort").fill("E2E cohort");
  await admin.getByRole("button", { name: "Mint code" }).click();
  const code = await admin
    .locator("input[readonly]")
    .first()
    .inputValue();
  expect(code).toMatch(/^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);

  // User redeems it — lowercase, to pin the normalization behavior.
  const user = await pageWith(browser, STORAGE.user);
  await user.goto("/badges/new/invite-code");
  await user.getByPlaceholder("ABCD-EFGH-JKLM").fill(code.toLowerCase());
  await user.getByRole("button", { name: "Redeem" }).click();
  await expect(user).toHaveURL(/\/profile/);
  await expect(user.getByRole("heading", { name: "Invited" })).toBeVisible();

  // Admin list reflects 1/1 used.
  await admin.goto("/admin/invite-codes");
  await expect(admin.getByText("1/1 used")).toBeVisible();

  // Exhausted: a different account gets the uniform rejection.
  await admin.goto("/badges/new/invite-code");
  await admin.getByPlaceholder("ABCD-EFGH-JKLM").fill(code);
  await admin.getByRole("button", { name: "Redeem" }).click();
  await expect(
    admin.getByText("Invalid, expired, or exhausted invite code."),
  ).toBeVisible();

  // Unknown codes get the same message — no oracle.
  await admin.getByPlaceholder("ABCD-EFGH-JKLM").fill("NOPE-NOPE-NOPE");
  await admin.getByRole("button", { name: "Redeem" }).click();
  await expect(
    admin.getByText("Invalid, expired, or exhausted invite code."),
  ).toBeVisible();

  await admin.context().close();
  await user.context().close();
});
