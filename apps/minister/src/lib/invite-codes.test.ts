import { describe, expect, it } from "vitest";

import {
  ALREADY_REDEEMED_MESSAGE,
  INVALID_CODE_MESSAGE,
  evaluateInviteCode,
  generateInviteCode,
  normalizeInviteCode,
  type InviteCodeView,
} from "./invite-codes";

const NOW = new Date("2026-06-11T12:00:00Z");

function view(overrides: Partial<InviteCodeView> = {}): InviteCodeView {
  return {
    usesTotal: 10,
    usesRemaining: 5,
    expiresAt: null,
    revokedAt: null,
    ...overrides,
  };
}

describe("generateInviteCode", () => {
  it("emits XXXX-XXXX-XXXX from the unambiguous alphabet", () => {
    for (let i = 0; i < 50; i++) {
      const code = generateInviteCode();
      expect(code).toMatch(/^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
      expect(code).not.toMatch(/[IO01]/);
    }
  });

  it("does not repeat across a small sample", () => {
    const seen = new Set(Array.from({ length: 200 }, generateInviteCode));
    expect(seen.size).toBe(200);
  });

  it("round-trips through normalizeInviteCode unchanged", () => {
    const code = generateInviteCode();
    expect(normalizeInviteCode(code)).toBe(code);
  });
});

describe("normalizeInviteCode", () => {
  it("trims and uppercases", () => {
    expect(normalizeInviteCode("  abcd-efgh-jklm \n")).toBe("ABCD-EFGH-JKLM");
  });

  it("keeps interior characters intact", () => {
    expect(normalizeInviteCode("summer-2026")).toBe("SUMMER-2026");
  });
});

describe("evaluateInviteCode", () => {
  it("accepts a live limited code with uses remaining", () => {
    expect(evaluateInviteCode(view(), false, NOW)).toEqual({ ok: true });
  });

  it("accepts an unlimited code regardless of usesRemaining", () => {
    expect(evaluateInviteCode(view({ usesTotal: 0, usesRemaining: 0 }), false, NOW)).toEqual({
      ok: true,
    });
  });

  it("rejects a revoked code", () => {
    const verdict = evaluateInviteCode(view({ revokedAt: new Date("2026-06-01") }), false, NOW);
    expect(verdict).toEqual({ ok: false, message: INVALID_CODE_MESSAGE });
  });

  it("rejects an expired code", () => {
    const verdict = evaluateInviteCode(view({ expiresAt: new Date("2026-06-10") }), false, NOW);
    expect(verdict).toEqual({ ok: false, message: INVALID_CODE_MESSAGE });
  });

  it("accepts a code expiring in the future", () => {
    expect(evaluateInviteCode(view({ expiresAt: new Date("2026-06-12") }), false, NOW)).toEqual({
      ok: true,
    });
  });

  it("rejects an exhausted limited code", () => {
    const verdict = evaluateInviteCode(view({ usesRemaining: 0 }), false, NOW);
    expect(verdict).toEqual({ ok: false, message: INVALID_CODE_MESSAGE });
  });

  it("rejects re-redemption with the distinct already-redeemed message", () => {
    const verdict = evaluateInviteCode(view(), true, NOW);
    expect(verdict).toEqual({ ok: false, message: ALREADY_REDEEMED_MESSAGE });
  });

  it("uses the uniform message for every state-based rejection", () => {
    // One assertion to pin the no-oracle property: revoked, expired,
    // and exhausted must be indistinguishable to the caller.
    const messages = [
      evaluateInviteCode(view({ revokedAt: NOW }), false, NOW),
      evaluateInviteCode(view({ expiresAt: new Date(0) }), false, NOW),
      evaluateInviteCode(view({ usesRemaining: 0 }), false, NOW),
    ].map((v) => (v.ok ? "" : v.message));
    expect(new Set(messages).size).toBe(1);
  });
});
