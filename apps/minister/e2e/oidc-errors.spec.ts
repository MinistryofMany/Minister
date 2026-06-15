import { expect, test } from "@playwright/test";

import { BASE_URL, STORAGE } from "./env";
import { createPublicOidcClient } from "./helpers";

// The authorize endpoint is gated by middleware, so every case runs as a
// signed-in user. The redirect_uri points back at the app's own origin
// (a 404 route) so redirect-style errors land on a reachable URL whose
// query string we can read.
test.use({ storageState: STORAGE.user });

const RP_CALLBACK = `${BASE_URL}/rp-callback`;

function authorizeUrl(params: Record<string, string>): string {
  const u = new URL(`${BASE_URL}/oidc/authorize`);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  return u.toString();
}

test("unknown client_id renders a fatal error, never redirects", async ({ page }) => {
  await page.goto(
    authorizeUrl({
      response_type: "code",
      client_id: "tc_does_not_exist",
      redirect_uri: RP_CALLBACK,
      scope: "openid",
      state: "s",
      nonce: "n",
      code_challenge: "x",
      code_challenge_method: "S256",
    }),
  );
  await expect(page.getByText("Unknown client")).toBeVisible();
  await expect(page).toHaveURL(/\/oidc\/authorize/); // stayed put
});

test("unregistered redirect_uri renders a fatal error (no open redirect)", async ({ page }) => {
  const clientId = await createPublicOidcClient(RP_CALLBACK, ["openid", "profile"]);
  await page.goto(
    authorizeUrl({
      response_type: "code",
      client_id: clientId,
      redirect_uri: "https://evil.example.com/steal",
      scope: "openid",
      state: "s",
      nonce: "n",
      code_challenge: "x",
      code_challenge_method: "S256",
    }),
  );
  await expect(page.getByText("Invalid redirect URI")).toBeVisible();
  await expect(page).toHaveURL(/\/oidc\/authorize/);
});

test("missing PKCE redirects back to the RP with error=invalid_request", async ({ page }) => {
  const clientId = await createPublicOidcClient(RP_CALLBACK, ["openid", "profile"]);
  await page.goto(
    authorizeUrl({
      response_type: "code",
      client_id: clientId,
      redirect_uri: RP_CALLBACK,
      scope: "openid",
      state: "the-state",
      nonce: "n",
      // no code_challenge
    }),
  );
  await page.waitForURL(/\/rp-callback\?/);
  const url = new URL(page.url());
  expect(url.searchParams.get("error")).toBe("invalid_request");
  expect(url.searchParams.get("state")).toBe("the-state");
});

test("denying consent redirects back to the RP with error=access_denied", async ({ page }) => {
  const clientId = await createPublicOidcClient(RP_CALLBACK, ["openid", "profile"]);
  await page.goto(
    authorizeUrl({
      response_type: "code",
      client_id: clientId,
      redirect_uri: RP_CALLBACK,
      scope: "openid profile",
      state: "deny-state",
      nonce: "n",
      code_challenge: "8Yh_IbRFk9tnnNGYK8yoY27Hsye_R5c1Op101N82F-o",
      code_challenge_method: "S256",
    }),
  );
  await expect(page.getByRole("heading", { name: "Approve access" })).toBeVisible();
  await page.getByRole("button", { name: "Deny" }).click();
  await page.waitForURL(/\/rp-callback\?/);
  const url = new URL(page.url());
  expect(url.searchParams.get("error")).toBe("access_denied");
  expect(url.searchParams.get("state")).toBe("deny-state");
});
