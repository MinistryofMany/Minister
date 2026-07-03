import { afterEach, describe, expect, it } from "vitest";

import { githubPlugin } from "./github";
import { isPluginConfigured, listAvailablePlugins, listPlugins } from "./registry";

describe("plugin config availability", () => {
  const origId = process.env.GITHUB_CLIENT_ID;
  const origSecret = process.env.GITHUB_CLIENT_SECRET;

  afterEach(() => {
    if (origId === undefined) delete process.env.GITHUB_CLIENT_ID;
    else process.env.GITHUB_CLIENT_ID = origId;
    if (origSecret === undefined) delete process.env.GITHUB_CLIENT_SECRET;
    else process.env.GITHUB_CLIENT_SECRET = origSecret;
  });

  it("hides github from the add-badge menu when OAuth creds are absent", () => {
    delete process.env.GITHUB_CLIENT_ID;
    delete process.env.GITHUB_CLIENT_SECRET;

    expect(isPluginConfigured(githubPlugin)).toBe(false);
    expect(listAvailablePlugins().map((p) => p.manifest.id)).not.toContain("github");
    // Still registered for internal lookup — just not offered to the user.
    expect(listPlugins().map((p) => p.manifest.id)).toContain("github");
  });

  it("offers github once both creds are present", () => {
    process.env.GITHUB_CLIENT_ID = "test_id";
    process.env.GITHUB_CLIENT_SECRET = "test_secret";

    expect(isPluginConfigured(githubPlugin)).toBe(true);
    expect(listAvailablePlugins().map((p) => p.manifest.id)).toContain("github");
  });

  it("hides github when only one of the two creds is set", () => {
    process.env.GITHUB_CLIENT_ID = "test_id";
    delete process.env.GITHUB_CLIENT_SECRET;
    expect(isPluginConfigured(githubPlugin)).toBe(false);

    delete process.env.GITHUB_CLIENT_ID;
    process.env.GITHUB_CLIENT_SECRET = "test_secret";
    expect(isPluginConfigured(githubPlugin)).toBe(false);
  });

  it("treats plugins without an isConfigured probe as always available", () => {
    const emailDomain = listPlugins().find((p) => p.manifest.id === "email-domain");
    expect(emailDomain).toBeDefined();
    expect(emailDomain?.isConfigured).toBeUndefined();
    expect(isPluginConfigured(emailDomain!)).toBe(true);
  });
});
