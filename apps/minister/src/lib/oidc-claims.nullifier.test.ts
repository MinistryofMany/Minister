import { beforeEach, describe, expect, it, vi } from "vitest";

// M5 disclosure wiring: loadApprovedBadgeJwts must derive the per-RP nullifier
// for ref-bearing badges, thread it into reMintVc, verify the drift cache, and
// FAIL CLOSED (omit the badge, never a nullifier-less copy) on any failure. The
// signature binding itself is covered by packages/vc remint.test.ts; here we
// mock reMintVc to observe exactly what the disclosure seam feeds it.

const h = vi.hoisted(
  () =>
    ({
      findMany: vi.fn(),
      userFindUnique: vi.fn(),
      reMintVc: vi.fn(),
      disclose: vi.fn(),
      assertDrift: vi.fn(),
      audit: vi.fn(),
      // Populated by the drift-cache mock factory below (a real constructor the
      // tests instantiate to exercise the dedicated drift-alert path).
      DriftError: undefined as unknown as new (
        entryRef: string,
        clientId: string,
        detail: string,
      ) => Error,
    }) as {
      findMany: ReturnType<typeof vi.fn>;
      userFindUnique: ReturnType<typeof vi.fn>;
      reMintVc: ReturnType<typeof vi.fn>;
      disclose: ReturnType<typeof vi.fn>;
      assertDrift: ReturnType<typeof vi.fn>;
      audit: ReturnType<typeof vi.fn>;
      DriftError: new (entryRef: string, clientId: string, detail: string) => Error;
    },
);

vi.mock("@/lib/prisma", () => ({
  prisma: {
    badge: { findMany: h.findMany },
    user: { findUnique: h.userFindUnique },
  },
}));
vi.mock("@minister/vc", () => ({
  reMintVc: h.reMintVc,
  buildPairwiseUserDid: (domain: string, sub: string) => `did:web:${domain}:u:${sub}`,
}));
vi.mock("@/lib/issuer", () => ({
  getIssuer: async () => ({ did: "did:web:ministry.test", domain: "ministry.test" }),
}));
vi.mock("@/lib/oidc-tokens", () => ({
  ACCESS_TOKEN_TTL: 3600,
}));
// The per-RP jti now routes through the Phase 7 pairwise seam (async); mock it
// deterministically, standing in for local mode's byte-identical derivation.
vi.mock("@/lib/pairwise-backend", () => ({
  derivePairwiseJti: (badgeId: string, clientId: string) =>
    Promise.resolve(`jti:${badgeId}:${clientId}`),
}));
vi.mock("@/lib/disclosure-claims", () => ({
  sanitizeDisclosedClaims: (claims: Record<string, unknown>) => claims,
}));
vi.mock("@/lib/nullifier", () => ({
  nullifierService: { disclose: h.disclose },
}));
// oidc-claims imports NullifierDriftError and branches on `instanceof`, so the
// mock must export a real constructor. Defined INSIDE the factory (vi.mock is
// hoisted above module-level declarations, so a top-level class would not yet be
// initialized when the factory runs). Re-exported to the test via h.DriftError.
vi.mock("@/lib/nullifier/drift-cache", () => {
  class NullifierDriftError extends Error {
    entryRef: string;
    clientId: string;
    constructor(entryRef: string, clientId: string, detail: string) {
      super(`nullifier drift detected for entryRef ${entryRef} at client ${clientId}: ${detail}`);
      this.name = "NullifierDriftError";
      this.entryRef = entryRef;
      this.clientId = clientId;
    }
  }
  h.DriftError = NullifierDriftError;
  return {
    assertNullifierDriftConsistent: h.assertDrift,
    NullifierDriftError,
  };
});
vi.mock("@/lib/audit", () => ({ audit: h.audit }));

import { loadApprovedBadgeJwts } from "@/lib/oidc-claims";

const CLIENT = "mc_client";
const SUB = "PAIRWISE_SUB";

beforeEach(() => {
  for (const v of Object.values(h)) {
    if (typeof v === "function" && "mockReset" in v) {
      (v as ReturnType<typeof vi.fn>).mockReset();
    }
  }
  h.reMintVc.mockImplementation(async (_issuer, vcJwt: string) => `minted(${vcJwt})`);
  h.disclose.mockResolvedValue("mnv1:DISCLOSED_value" as never);
  h.assertDrift.mockResolvedValue(undefined);
  h.userFindUnique.mockResolvedValue({ dedupHandle: "owner-handle" });
});

describe("loadApprovedBadgeJwts — nullifier disclosure", () => {
  it("derives, drift-checks, and threads the nullifier for a ref-bearing badge", async () => {
    h.findMany.mockResolvedValue([
      { id: "b1", vcJwt: "vc1", expiresAt: null, nullifierRef: "ref-1" },
    ]);

    const out = await loadApprovedBadgeJwts("user1", CLIENT, SUB, ["b1"]);

    expect(h.disclose).toHaveBeenCalledWith({
      entryRef: "ref-1",
      ownerHandle: "owner-handle",
      clientId: CLIENT,
    });
    expect(h.assertDrift).toHaveBeenCalledWith("ref-1", CLIENT, "mnv1:DISCLOSED_value");
    // reMintVc got the nullifier stamped in.
    const opts = h.reMintVc.mock.calls[0]![2] as { nullifier?: string };
    expect(opts.nullifier).toBe("mnv1:DISCLOSED_value");
    expect(out).toEqual(["minted(vc1)"]);
  });

  it("does NOT disclose or stamp a nullifier for a ref-less badge (unchanged path)", async () => {
    h.findMany.mockResolvedValue([{ id: "b1", vcJwt: "vc1", expiresAt: null, nullifierRef: null }]);

    const out = await loadApprovedBadgeJwts("user1", CLIENT, SUB, ["b1"]);

    expect(h.disclose).not.toHaveBeenCalled();
    expect(h.assertDrift).not.toHaveBeenCalled();
    const opts = h.reMintVc.mock.calls[0]![2] as { nullifier?: string };
    expect(opts.nullifier).toBeUndefined();
    expect(out).toEqual(["minted(vc1)"]);
  });

  it("FAILS CLOSED (omits the badge, audits) when disclose throws — never a nullifier-less copy", async () => {
    h.findMany.mockResolvedValue([
      { id: "b1", vcJwt: "vc1", expiresAt: null, nullifierRef: "ref-1" },
    ]);
    h.disclose.mockRejectedValue(new Error("signet down"));

    const out = await loadApprovedBadgeJwts("user1", CLIENT, SUB, ["b1"]);

    expect(out).toEqual([]);
    expect(h.reMintVc).not.toHaveBeenCalled();
    expect(h.audit).toHaveBeenCalledWith(
      "user1",
      "oidc.badge_disclosure_omitted",
      expect.objectContaining({ badgeId: "b1", clientId: CLIENT }),
    );
  });

  it("FAILS CLOSED on a drift-cache mismatch and raises a DEDICATED drift alert", async () => {
    h.findMany.mockResolvedValue([
      { id: "b1", vcJwt: "vc1", expiresAt: null, nullifierRef: "ref-1" },
    ]);
    h.assertDrift.mockRejectedValue(new h.DriftError("ref-1", CLIENT, "value changed"));

    const out = await loadApprovedBadgeJwts("user1", CLIENT, SUB, ["b1"]);

    expect(out).toEqual([]);
    expect(h.reMintVc).not.toHaveBeenCalled();
    // A drift emits its OWN action (alertable, not buried) AND the omission
    // record — never just the generic omission a benign schema failure produces.
    expect(h.audit).toHaveBeenCalledWith(
      "user1",
      "nullifier.drift_detected",
      expect.objectContaining({ badgeId: "b1", clientId: CLIENT }),
    );
    expect(h.audit).toHaveBeenCalledWith(
      "user1",
      "oidc.badge_disclosure_omitted",
      expect.objectContaining({ badgeId: "b1", clientId: CLIENT }),
    );
  });

  it("a BENIGN (non-drift) failure emits ONLY the generic omission, not the drift alert", async () => {
    h.findMany.mockResolvedValue([
      { id: "b1", vcJwt: "vc1", expiresAt: null, nullifierRef: "ref-1" },
    ]);
    h.disclose.mockRejectedValue(new Error("signet down"));

    await loadApprovedBadgeJwts("user1", CLIENT, SUB, ["b1"]);

    expect(h.audit).not.toHaveBeenCalledWith(
      "user1",
      "nullifier.drift_detected",
      expect.anything(),
    );
    expect(h.audit).toHaveBeenCalledWith(
      "user1",
      "oidc.badge_disclosure_omitted",
      expect.objectContaining({ badgeId: "b1" }),
    );
  });

  it("still omits (never throws) when the audit write itself fails — login stays up", async () => {
    h.findMany.mockResolvedValue([
      { id: "b1", vcJwt: "vc1", expiresAt: null, nullifierRef: "ref-1" },
    ]);
    h.disclose.mockRejectedValue(new Error("signet down"));
    h.audit.mockRejectedValue(new Error("db degraded"));

    // A bare audit reject would otherwise escape into Promise.all and fail the
    // whole token request; safeAudit must swallow it.
    const out = await loadApprovedBadgeJwts("user1", CLIENT, SUB, ["b1"]);
    expect(out).toEqual([]);
  });

  it("FAILS CLOSED when a ref-bearing badge has no owner handle (never a nullifier-less copy)", async () => {
    h.userFindUnique.mockResolvedValue({ dedupHandle: null });
    h.findMany.mockResolvedValue([
      { id: "b1", vcJwt: "vc1", expiresAt: null, nullifierRef: "ref-1" },
    ]);

    const out = await loadApprovedBadgeJwts("user1", CLIENT, SUB, ["b1"]);

    expect(out).toEqual([]);
    expect(h.disclose).not.toHaveBeenCalled();
    expect(h.audit).toHaveBeenCalledOnce();
  });

  it("omits only the failing badge; other badges still disclose", async () => {
    h.findMany.mockResolvedValue([
      { id: "b1", vcJwt: "vc1", expiresAt: null, nullifierRef: "ref-1" },
      { id: "b2", vcJwt: "vc2", expiresAt: null, nullifierRef: null },
    ]);
    h.disclose.mockRejectedValue(new Error("signet down"));

    const out = await loadApprovedBadgeJwts("user1", CLIENT, SUB, ["b1", "b2"]);

    // b1 (ref-bearing, disclose failed) omitted; b2 (ref-less) still disclosed.
    expect(out).toEqual(["minted(vc2)"]);
  });
});
