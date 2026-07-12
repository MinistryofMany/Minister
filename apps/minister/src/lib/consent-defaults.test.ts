import { describe, expect, it } from "vitest";

import { initialConsentDefaults } from "@/lib/consent-defaults";

describe("initialConsentDefaults", () => {
  it("pre-checks sybil-score on a FIRST consent (no prior grant)", () => {
    const d = initialConsentDefaults({
      wantsProfile: false,
      previouslyShared: { name: false, avatar: false },
      wantsSybilScore: true,
    });
    // The coarse, non-identifying bucket is default-checked so a user clicking
    // Approve without changing anything discloses it (a gating RP needs it).
    expect(d.sybilScore).toBe(true);
  });

  it("leaves sybil-score OFF when the scope was not requested", () => {
    const d = initialConsentDefaults({
      wantsProfile: false,
      previouslyShared: { name: false, avatar: false },
      wantsSybilScore: false,
    });
    expect(d.sybilScore).toBe(false);
  });

  it("keeps identifying profile fields OFF on a first consent", () => {
    const d = initialConsentDefaults({
      wantsProfile: true,
      previouslyShared: { name: false, avatar: false },
      wantsSybilScore: true,
    });
    expect(d.name).toBe(false);
    expect(d.avatar).toBe(false);
    // sybil-score is the ONLY thing pre-checked.
    expect(d.sybilScore).toBe(true);
  });

  it("pre-checks a profile field only on re-login where it was previously shared", () => {
    const d = initialConsentDefaults({
      wantsProfile: true,
      previouslyShared: { name: true, avatar: false },
      wantsSybilScore: false,
    });
    expect(d.name).toBe(true);
    expect(d.avatar).toBe(false);
  });

  it("never pre-checks a profile field the RP did not request this round (H-1)", () => {
    const d = initialConsentDefaults({
      wantsProfile: false,
      previouslyShared: { name: true, avatar: true },
      wantsSybilScore: false,
    });
    expect(d.name).toBe(false);
    expect(d.avatar).toBe(false);
  });
});
