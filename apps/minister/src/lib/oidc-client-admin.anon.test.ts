import { describe, expect, it } from "vitest";

import { resolveAnonAppIdUpdate, validateAnonAppId } from "@/lib/oidc-client-admin";

// anonAppId shape + immutability rules (anon-identity master spec §8.1, I7).

describe("validateAnonAppId", () => {
  it("empty/whitespace/absent → null (not anon-enabled)", () => {
    expect(validateAnonAppId(undefined)).toEqual({ ok: true, anonAppId: null });
    expect(validateAnonAppId(null)).toEqual({ ok: true, anonAppId: null });
    expect(validateAnonAppId("")).toEqual({ ok: true, anonAppId: null });
    expect(validateAnonAppId("   ")).toEqual({ ok: true, anonAppId: null });
  });

  it("accepts a valid lowercase slug (trimmed)", () => {
    expect(validateAnonAppId("deforum")).toEqual({ ok: true, anonAppId: "deforum" });
    expect(validateAnonAppId("  free-dink  ")).toEqual({ ok: true, anonAppId: "free-dink" });
  });

  it("rejects uppercase, spaces, colons, too-short, too-long", () => {
    for (const bad of ["Deforum", "def orum", "ab", "a".repeat(33), "app:1", "under_score"]) {
      expect(validateAnonAppId(bad).ok).toBe(false);
    }
  });
});

describe("resolveAnonAppIdUpdate (immutable once set)", () => {
  it("null → slug is a permitted first-set", () => {
    expect(resolveAnonAppIdUpdate(null, "deforum")).toEqual({ ok: true, set: "deforum" });
  });

  it("null → null leaves it unset", () => {
    expect(resolveAnonAppIdUpdate(null, null)).toEqual({ ok: true, set: null });
  });

  it("a SET value is never overwritten by a blank submit (stays untouched)", () => {
    expect(resolveAnonAppIdUpdate("deforum", null)).toEqual({ ok: true, set: null });
  });

  it("repeating the current value is a no-op (untouched, allowed)", () => {
    expect(resolveAnonAppIdUpdate("deforum", "deforum")).toEqual({ ok: true, set: null });
  });

  it("CHANGING a set value is rejected (I7 — would fork every identity)", () => {
    const r = resolveAnonAppIdUpdate("deforum", "freedink");
    expect(r.ok).toBe(false);
  });
});
