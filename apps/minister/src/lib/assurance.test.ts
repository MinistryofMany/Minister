import { describe, expect, it } from "vitest";

import {
  aalForCredential,
  assuranceLevelFor,
  BADGE_ASSURANCE_WEIGHT,
  CREDENTIAL_QUARANTINE_MS,
  MERGE_REVERSAL_DAYS,
  RECOVERY_CODE_COUNT,
  RECOVERY_ELIGIBLE_TYPES,
  RECOVERY_THRESHOLD,
  recoveryWeightFor,
} from "./assurance";

describe("aalForCredential", () => {
  it("passkey is AAL2 (phishing-resistant)", () => {
    expect(aalForCredential("passkey")).toBe(2);
  });

  it("totp is AAL2 (paired second factor)", () => {
    expect(aalForCredential("totp")).toBe(2);
  });

  it("email magic link is AAL1", () => {
    expect(aalForCredential("email")).toBe(1);
  });

  it("recovery code is AAL1", () => {
    expect(aalForCredential("recovery-code")).toBe(1);
  });
});

describe("constants", () => {
  it("quarantine window is 72h in ms", () => {
    expect(CREDENTIAL_QUARANTINE_MS).toBe(72 * 60 * 60 * 1000);
  });

  it("merge reversal window is 7 days", () => {
    expect(MERGE_REVERSAL_DAYS).toBe(7);
  });

  it("generates 10 recovery codes", () => {
    expect(RECOVERY_CODE_COUNT).toBe(10);
  });

  it("recovery threshold is 100", () => {
    expect(RECOVERY_THRESHOLD).toBe(100);
  });

  it("BADGE_ASSURANCE_WEIGHT maps each IAL to its weight", () => {
    expect(BADGE_ASSURANCE_WEIGHT).toEqual({ IAL0: 0, IAL1: 15, IAL2: 60, IAL3: 100 });
  });
});

describe("assuranceLevelFor", () => {
  it("tlsn-attestation is IAL3", () => {
    expect(assuranceLevelFor("tlsn-attestation")).toBe("IAL3");
  });

  it("age-over-* and residency-* are IAL2", () => {
    expect(assuranceLevelFor("age-over-21")).toBe("IAL2");
    expect(assuranceLevelFor("age-over-18")).toBe("IAL2");
    expect(assuranceLevelFor("residency-state")).toBe("IAL2");
  });

  it("oauth-account is IAL1 regardless of provenance", () => {
    expect(assuranceLevelFor("oauth-account")).toBe("IAL1");
    expect(assuranceLevelFor("oauth-account", "discord")).toBe("IAL1");
    expect(assuranceLevelFor("oauth-account", "github")).toBe("IAL1");
  });

  it("email-domain and email-exact are IAL1", () => {
    expect(assuranceLevelFor("email-domain")).toBe("IAL1");
    expect(assuranceLevelFor("email-exact")).toBe("IAL1");
  });

  it("invite-code is IAL0", () => {
    expect(assuranceLevelFor("invite-code")).toBe("IAL0");
  });

  it("unknown types default to IAL1", () => {
    expect(assuranceLevelFor("some-future-type")).toBe("IAL1");
  });
});

describe("recoveryWeightFor", () => {
  it("tlsn-attestation contributes 100 (IAL3)", () => {
    expect(recoveryWeightFor("tlsn-attestation")).toBe(100);
  });

  it("age/residency contribute 60 via the IAL2 baseline", () => {
    expect(recoveryWeightFor("age-over-21")).toBe(60);
    expect(recoveryWeightFor("residency-state")).toBe(60);
  });

  it("oauth github/google contribute 20", () => {
    expect(recoveryWeightFor("oauth-account", "github")).toBe(20);
    expect(recoveryWeightFor("oauth-account", "google")).toBe(20);
  });

  it("oauth discord/steam contribute 10", () => {
    expect(recoveryWeightFor("oauth-account", "discord")).toBe(10);
    expect(recoveryWeightFor("oauth-account", "steam")).toBe(10);
  });

  it("oauth with no provenance defaults to 20", () => {
    expect(recoveryWeightFor("oauth-account")).toBe(20);
  });

  it("email-domain/email-exact contribute 15", () => {
    expect(recoveryWeightFor("email-domain")).toBe(15);
    expect(recoveryWeightFor("email-exact")).toBe(15);
  });

  it("invite-code contributes 0", () => {
    expect(recoveryWeightFor("invite-code")).toBe(0);
  });

  it("unknown types contribute the IAL1 baseline (15)", () => {
    expect(recoveryWeightFor("some-future-type")).toBe(15);
  });
});

describe("threshold reachability sanity", () => {
  it("a single IAL3 proof meets the threshold alone", () => {
    expect(recoveryWeightFor("tlsn-attestation")).toBe(RECOVERY_THRESHOLD);
  });

  it("two IAL2 proofs exceed the threshold", () => {
    expect(recoveryWeightFor("age-over-21") + recoveryWeightFor("residency-state")).toBeGreaterThan(
      RECOVERY_THRESHOLD,
    );
  });

  it("four github OAuth links fall short; five clear it", () => {
    const per = recoveryWeightFor("oauth-account", "github");
    expect(per * 4).toBeLessThan(RECOVERY_THRESHOLD);
    expect(per * 5).toBeGreaterThanOrEqual(RECOVERY_THRESHOLD);
  });

  it("a single low-IAL factor can never recover alone", () => {
    expect(recoveryWeightFor("oauth-account", "discord")).toBeLessThan(RECOVERY_THRESHOLD);
    expect(recoveryWeightFor("email-domain")).toBeLessThan(RECOVERY_THRESHOLD);
  });

  it("invite-code adds nothing toward the threshold", () => {
    expect(recoveryWeightFor("invite-code")).toBe(0);
  });
});

describe("RECOVERY_ELIGIBLE_TYPES", () => {
  it("includes the live-reprovable types", () => {
    expect(RECOVERY_ELIGIBLE_TYPES.has("oauth-account")).toBe(true);
    expect(RECOVERY_ELIGIBLE_TYPES.has("email-domain")).toBe(true);
    expect(RECOVERY_ELIGIBLE_TYPES.has("email-exact")).toBe(true);
    expect(RECOVERY_ELIGIBLE_TYPES.has("tlsn-attestation")).toBe(true);
  });

  it("excludes invite-code (one-shot, not re-provable)", () => {
    expect(RECOVERY_ELIGIBLE_TYPES.has("invite-code")).toBe(false);
  });
});
