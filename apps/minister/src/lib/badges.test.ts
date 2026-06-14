import { describe, expect, it } from "vitest";

import { summarizeAttributes } from "./badges";

describe("summarizeAttributes", () => {
  it("returns the domain for email-domain", () => {
    expect(
      summarizeAttributes("email-domain", { domain: "example.com" }),
    ).toBe("example.com");
  });

  it("returns the email for email-exact", () => {
    expect(
      summarizeAttributes("email-exact", { email: "alice@example.com" }),
    ).toBe("alice@example.com");
  });

  it("joins provider + handle for oauth-account", () => {
    expect(
      summarizeAttributes("oauth-account", {
        provider: "github",
        accountId: "1",
        handle: "octocat",
      }),
    ).toBe("github · @octocat");
  });

  it("omits the handle when missing for oauth-account", () => {
    expect(
      summarizeAttributes("oauth-account", {
        provider: "github",
        accountId: "1",
      }),
    ).toBe("github");
  });

  it("summarizes age-over-N from the slug", () => {
    expect(summarizeAttributes("age-over-21", {})).toBe("Over 21");
  });

  it("returns just the country for residency-country", () => {
    expect(summarizeAttributes("residency-country", { country: "US" })).toBe(
      "US",
    );
  });

  it("joins state + country for residency-state", () => {
    expect(
      summarizeAttributes("residency-state", { country: "US", state: "MD" }),
    ).toBe("MD, US");
  });

  it("joins city + state + country for residency-city", () => {
    expect(
      summarizeAttributes("residency-city", {
        country: "US",
        state: "MD",
        city: "Baltimore",
      }),
    ).toBe("Baltimore, MD, US");
  });

  it("returns empty string for unknown type", () => {
    expect(summarizeAttributes("not-a-real-type", { foo: "bar" })).toBe("");
  });

  it("tolerates missing fields without throwing", () => {
    expect(summarizeAttributes("email-domain", {})).toBe("");
    expect(summarizeAttributes("residency-state", {})).toBe("");
  });
});
