import { test as setup } from "@playwright/test";

import { ADMIN_EMAIL, STORAGE, USER_EMAIL } from "./env";
import { grantAdmin, signInViaMagicLink } from "./helpers";

// Mint the two long-lived sessions the specs reuse. Saves ~10 magic
// link round-trips per run and keeps the per-IP sign-in rate limiter
// out of the picture.

setup("user session", async ({ page }) => {
  await signInViaMagicLink(page, USER_EMAIL);
  await page.context().storageState({ path: STORAGE.user });
});

setup("admin session", async ({ page }) => {
  await signInViaMagicLink(page, ADMIN_EMAIL);
  // Bootstrap path — equivalent of scripts/make-admin.ts. The
  // promote-from-UI path is covered in admin.spec.ts.
  await grantAdmin(ADMIN_EMAIL);
  await page.context().storageState({ path: STORAGE.admin });
});
