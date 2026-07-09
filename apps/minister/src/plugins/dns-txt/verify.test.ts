import { describe, expect, it } from "vitest";

import {
  buildDomainControlBadge,
  challengeHost,
  challengeValue,
  normalizeDomain,
  txtRecordsContainChallenge,
} from "./verify";

describe("normalizeDomain", () => {
  it("accepts and lowercases a plain public hostname", () => {
    expect(normalizeDomain("Example.COM")).toBe("example.com");
    expect(normalizeDomain("  sub.example.co.uk  ")).toBe("sub.example.co.uk");
    expect(normalizeDomain("a-b.example.com")).toBe("a-b.example.com");
  });

  it("strips a single trailing FQDN dot", () => {
    expect(normalizeDomain("example.com.")).toBe("example.com");
  });

  it("rejects URLs, ports, and userinfo (not bare hostnames)", () => {
    expect(normalizeDomain("https://example.com")).toBeNull();
    expect(normalizeDomain("example.com/path")).toBeNull();
    expect(normalizeDomain("example.com:8080")).toBeNull();
    expect(normalizeDomain("user@example.com")).toBeNull();
    expect(normalizeDomain("example.com?q=1")).toBeNull();
    expect(normalizeDomain("exa mple.com")).toBeNull();
  });

  it("rejects IP addresses", () => {
    expect(normalizeDomain("192.168.0.1")).toBeNull(); // numeric TLD
    expect(normalizeDomain("::1")).toBeNull(); // IPv6 (colon)
    expect(normalizeDomain("2001:db8::1")).toBeNull();
  });

  it("rejects single-label and internal names", () => {
    expect(normalizeDomain("localhost")).toBeNull();
    expect(normalizeDomain("intranet")).toBeNull();
    expect(normalizeDomain("")).toBeNull();
    expect(normalizeDomain("   ")).toBeNull();
  });

  it("rejects empty labels and hyphen-edge labels", () => {
    expect(normalizeDomain("a..b.com")).toBeNull();
    expect(normalizeDomain(".example.com")).toBeNull();
    expect(normalizeDomain("-example.com")).toBeNull();
    expect(normalizeDomain("example-.com")).toBeNull();
    expect(normalizeDomain("example..")).toBeNull();
  });

  it("rejects underscores in the user domain", () => {
    expect(normalizeDomain("under_score.com")).toBeNull();
  });

  it("rejects an over-length name", () => {
    const tooLong = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.com`;
    expect(tooLong.length).toBeGreaterThan(253);
    expect(normalizeDomain(tooLong)).toBeNull();
  });
});

describe("challengeHost / challengeValue", () => {
  it("builds the dedicated challenge host and value", () => {
    expect(challengeHost("example.com")).toBe("_minister-challenge.example.com");
    expect(challengeValue("abc123")).toBe("minister-verification=abc123");
  });
});

describe("txtRecordsContainChallenge", () => {
  const expected = challengeValue("tok-XYZ");

  it("matches a single-chunk record", () => {
    expect(txtRecordsContainChallenge([[expected]], expected)).toBe(true);
  });

  it("matches a record split into multiple chunks (joined)", () => {
    const [a, b] = [expected.slice(0, 5), expected.slice(5)];
    expect(txtRecordsContainChallenge([[a, b]], expected)).toBe(true);
  });

  it("matches when other unrelated TXT records are present", () => {
    expect(
      txtRecordsContainChallenge([["v=spf1 -all"], [expected], ["other=thing"]], expected),
    ).toBe(true);
  });

  it("tolerates trailing whitespace on the record", () => {
    expect(txtRecordsContainChallenge([[`${expected}  `]], expected)).toBe(true);
  });

  it("is false when the token differs or is absent", () => {
    expect(txtRecordsContainChallenge([[challengeValue("wrong")]], expected)).toBe(false);
    expect(txtRecordsContainChallenge([["v=spf1 -all"]], expected)).toBe(false);
    expect(txtRecordsContainChallenge([], expected)).toBe(false);
  });

  it("is false for an empty expected value", () => {
    expect(txtRecordsContainChallenge([[""]], "")).toBe(false);
  });
});

describe("buildDomainControlBadge", () => {
  it("anchors on the domain and reveals it (domain IS the disclosed value)", () => {
    const badge = buildDomainControlBadge("example.com");
    expect(badge.type).toBe("domain-control");
    expect(badge.claims).toEqual({ domain: "example.com" });
    expect(badge.attributes).toEqual({ domain: "example.com" });
    expect(badge.sybilAnchor).toBe("example.com");
    // The domain is both anchor and disclosed claim, so the anchor-leak guard
    // must be opted out of, or issuance would refuse this badge.
    expect(badge.revealsAnchor).toBe(true);
  });
});
