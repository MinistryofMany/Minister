import { expect, test } from "@playwright/test";

import { STORAGE } from "./env";
import { ANON_STATE, acceptDialogs, issueEmailDomainBadge } from "./helpers";

test.use({ storageState: STORAGE.user });

test("share link: create, anonymous view, revoke, unavailable", async ({
  page,
  browser,
}) => {
  // Self-contained: make sure the user holds at least one badge.
  await issueEmailDomainBadge(page, "share-proof@example-corp.com");

  await page.goto("/shares");
  await page.locator('input[type="checkbox"]').first().check();
  await page.getByRole("button", { name: "Create share link" }).click();
  const url = await page.locator("input[readonly]").first().inputValue();
  expect(url).toMatch(/\/share\/[A-Za-z0-9_-]{43}$/);

  // Anonymous viewer sees the shared badge.
  const anon = await browser.newContext({ storageState: ANON_STATE });
  const anonPage = await anon.newPage();
  await anonPage.goto(url);
  await expect(
    anonPage.getByRole("heading", { name: "Email domain" }),
  ).toBeVisible();

  // Revoke; the same URL goes dark without admitting why.
  acceptDialogs(page);
  await page.goto("/shares");
  await page
    .getByRole("button", { name: "Revoke this share link" })
    .first()
    .click();
  await expect(page.getByText("revoked").first()).toBeVisible();

  await anonPage.goto(url);
  await expect(
    anonPage.getByRole("heading", { name: "Link unavailable" }),
  ).toBeVisible();
  await anon.close();
});
