import { beforeEach, describe, expect, it, vi } from "vitest";

// M5 disclosure wiring: loadApprovedBadgeJwts must derive the per-RP nullifier
// for ref-bearing badges, thread it into reMintVc, verify the drift cache, and
// FAIL CLOSED (omit the badge, never a nullifier-less copy) on any failure. The
// signature binding itself is covered by packages/vc remint.test.ts; here we
// mock reMintVc to observe exactly what the disclosure seam feeds it.

const h = vi.hoisted(() => ({
  findMany: vi.fn(),
  userFindUnique: vi.fn(),
  reMintVc: vi.fn(),
  disclose: vi.fn(),
  assertDrift: vi.fn(),
  audit: vi.fn(),
}));

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
  pairwiseJti: (badgeId: string, clientId: string) => `jti:${badgeId}:${clientId}`,
}));
vi.mock("@/lib/disclosure-claims", () => ({
  sanitizeDisclosedClaims: (claims: Record<string, unknown>) => claims,
}));
vi.mock("@/lib/nullifier", () => ({
  nullifierService: { disclose: h.disclose },
}));
vi.mock("@/lib/nullifier/drift-cache", () => ({
  assertNullifierDriftConsistent: h.assertDrift,
}));
vi.mock("@/lib/audit", () => ({ audit: h.audit }));

import { loadApprovedBadgeJwts } from "@/lib/oidc-claims";

const CLIENT = "mc_client";
const SUB = "PAIRWISE_SUB";

beforeEach(() => {
  Object.values(h).forEach((fn) => fn.mockReset());
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

  it("FAILS CLOSED on a drift-cache mismatch", async () => {
    h.findMany.mockResolvedValue([
      { id: "b1", vcJwt: "vc1", expiresAt: null, nullifierRef: "ref-1" },
    ]);
    h.assertDrift.mockRejectedValue(new Error("drift detected"));

    const out = await loadApprovedBadgeJwts("user1", CLIENT, SUB, ["b1"]);

    expect(out).toEqual([]);
    expect(h.reMintVc).not.toHaveBeenCalled();
    expect(h.audit).toHaveBeenCalledOnce();
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
