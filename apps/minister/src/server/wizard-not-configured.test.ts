import { afterEach, describe, expect, it } from "vitest";

// Defense-in-depth regression for TODO #29: an unconfigured OAuth plugin
// (e.g. github with no GITHUB_CLIENT_ID/SECRET) must never reach the
// plugin's own startWizard() and throw an unhandled error out of the
// wizard runtime. The add-a-badge menu already filters it out and the
// wizard page route already 404s before calling startWizard — this pins
// the backstop inside startWizard() itself, so any other caller gets the
// same clean, named failure.
import { PluginNotConfiguredError, startWizard } from "./wizard";

describe("startWizard — unconfigured plugin guard", () => {
  const origId = process.env.GITHUB_CLIENT_ID;
  const origSecret = process.env.GITHUB_CLIENT_SECRET;

  afterEach(() => {
    if (origId === undefined) delete process.env.GITHUB_CLIENT_ID;
    else process.env.GITHUB_CLIENT_ID = origId;
    if (origSecret === undefined) delete process.env.GITHUB_CLIENT_SECRET;
    else process.env.GITHUB_CLIENT_SECRET = origSecret;
  });

  it("throws a named PluginNotConfiguredError instead of reaching the plugin's own startWizard", async () => {
    delete process.env.GITHUB_CLIENT_ID;
    delete process.env.GITHUB_CLIENT_SECRET;

    await expect(startWizard("github", "user_test", "http://localhost:3000")).rejects.toThrow(
      PluginNotConfiguredError,
    );
  });

  it("rejects with a message naming the plugin, no secret material", async () => {
    delete process.env.GITHUB_CLIENT_ID;
    delete process.env.GITHUB_CLIENT_SECRET;

    await expect(startWizard("github", "user_test", "http://localhost:3000")).rejects.toThrow(
      /github/i,
    );
  });
});
