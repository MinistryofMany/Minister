import { describe, expect, it } from "vitest";

import { domainFromEmail, isFreemailDomain } from "./freemail-domains";

describe("isFreemailDomain", () => {
  it("flags well-known consumer mailbox providers", () => {
    for (const d of ["gmail.com", "icloud.com", "outlook.com", "proton.me", "pm.me"]) {
      expect(isFreemailDomain(d)).toBe(true);
    }
  });

  it("does not flag plausible org / personal domains", () => {
    for (const d of ["acme.com", "mit.edu", "heart.engineering", "example.org"]) {
      expect(isFreemailDomain(d)).toBe(false);
    }
  });

  it("matches case-insensitively", () => {
    expect(isFreemailDomain("Gmail.COM")).toBe(true);
  });
});

describe("domainFromEmail", () => {
  it("extracts and lowercases the host", () => {
    expect(domainFromEmail("Alice@Example.COM")).toBe("example.com");
  });

  it("uses the last @ so plus/subaddressed locals don't confuse it", () => {
    expect(domainFromEmail("a@b@work.test")).toBe("work.test");
  });

  it("returns null for malformed addresses", () => {
    expect(domainFromEmail("no-at-sign")).toBeNull();
    expect(domainFromEmail("trailing@")).toBeNull();
  });
});
