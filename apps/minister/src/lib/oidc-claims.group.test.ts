import { beforeEach, describe, expect, it, vi } from "vitest";

// The load-bearing revocation seam: loadApprovedBadgeJwts re-checks the LIVE
// GroupMembership row before re-minting a group-membership badge.
//   - member present        -> disclosed, role from the live row
//   - member removed (no row)-> OMITTED (never disclosed), audited
//   - role changed           -> re-minted with the NEW role (overriding the
//                               value baked into the stored VC at issuance)
// reMintVc is mocked so we can observe exactly the sanitizeClaims hook the seam
// feeds it; the real sanitizeDisclosedClaims (schema.parse) runs underneath the
// role override, so the composition is exercised for real.

const CRED_TYPE = ["VerifiableCredential", "MinisterGroupMembershipCredential"];

const h = vi.hoisted(() => ({
  findMany: vi.fn(),
  userFindUnique: vi.fn(),
  membershipFindUnique: vi.fn(),
  reMintVc: vi.fn(),
  audit: vi.fn(),
  allocateStatusEntry: vi.fn(),
}));

vi.mock("@/lib/prisma", () => ({
  prisma: {
    badge: { findMany: h.findMany },
    user: { findUnique: h.userFindUnique },
    groupMembership: { findUnique: h.membershipFindUnique },
  },
}));

function pascal(slug: string): string {
  return slug
    .split("-")
    .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
    .join("");
}

vi.mock("@minister/vc", () => ({
  reMintVc: h.reMintVc,
  buildPairwiseUserDid: (domain: string, sub: string) => `did:web:${domain}:u:${sub}`,
  // Real transform so the real sanitizeDisclosedClaims maps group-membership to
  // its schema (needed for the role-override composition to run for real).
  ministerCredentialType: (badgeType: string) => `Minister${pascal(badgeType)}Credential`,
}));

vi.mock("@/lib/issuer", () => ({
  getIssuer: vi.fn(async () => ({
    did: "did:web:ministry.id",
    domain: "ministry.id",
    publicKey: {},
  })),
}));
vi.mock("@/lib/oidc-tokens", () => ({ ACCESS_TOKEN_TTL: 3600 }));
vi.mock("@/lib/pairwise-backend", () => ({ derivePairwiseJti: vi.fn(async () => "jti-1") }));
vi.mock("@/lib/nullifier", () => ({ nullifierService: { disclose: vi.fn() } }));
vi.mock("@/lib/nullifier/drift-cache", () => ({
  assertNullifierDriftConsistent: vi.fn(),
  NullifierDriftError: class NullifierDriftError extends Error {},
}));
vi.mock("@/lib/audit", () => ({ audit: h.audit }));
vi.mock("@/lib/status-list", () => ({
  allocateStatusEntry: h.allocateStatusEntry,
  credentialStatusFor: (listId: string, bitIndex: number) => ({
    id: `https://ministry.id/status/${listId}#${bitIndex}`,
    type: "BitstringStatusListEntry",
    statusPurpose: "revocation",
    statusListIndex: String(bitIndex),
    statusListCredential: `https://ministry.id/status/${listId}`,
  }),
}));

import { loadApprovedBadgeJwts } from "./oidc-claims";

const USER = "user-1";
const CLIENT = "client-1";
const SUB = "pairwise-sub";

function groupBadgeRow(role: string) {
  return {
    id: "badge-1",
    vcJwt: "stored-vc",
    expiresAt: null,
    nullifierRef: null,
    type: "group-membership",
    attributes: { group: "acme", role, groupId: "grp-1" },
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  h.userFindUnique.mockResolvedValue(null);
  h.reMintVc.mockResolvedValue("reminted-vc");
});

describe("group-membership disclosure re-check", () => {
  it("discloses the badge when the live membership exists (role from the live row)", async () => {
    h.findMany.mockResolvedValue([groupBadgeRow("member")]);
    h.membershipFindUnique.mockResolvedValue({ role: "member" });

    const out = await loadApprovedBadgeJwts(USER, CLIENT, SUB, ["badge-1"]);

    expect(out).toEqual(["reminted-vc"]);
    expect(h.membershipFindUnique).toHaveBeenCalledWith({
      where: { groupId_userId: { groupId: "grp-1", userId: USER } },
      select: { role: true },
    });
    // The hook fed to reMintVc keeps the (still-current) role.
    const sanitize = h.reMintVc.mock.calls[0]![2].sanitizeClaims;
    expect(sanitize({ group: "acme", role: "member", groupId: "grp-1" }, CRED_TYPE)).toEqual({
      group: "acme",
      role: "member",
      groupId: "grp-1",
    });
  });

  it("OMITS the badge (and audits) when the membership row is gone", async () => {
    h.findMany.mockResolvedValue([groupBadgeRow("member")]);
    h.membershipFindUnique.mockResolvedValue(null);

    const out = await loadApprovedBadgeJwts(USER, CLIENT, SUB, ["badge-1"]);

    expect(out).toEqual([]);
    expect(h.reMintVc).not.toHaveBeenCalled();
    expect(h.audit).toHaveBeenCalledWith(
      USER,
      "group.membership_disclosure_omitted",
      expect.objectContaining({ badgeId: "badge-1", clientId: CLIENT, groupId: "grp-1" }),
    );
  });

  it("re-mints with the NEW role when the live row's role changed", async () => {
    // Stored VC was issued as `member`; the live row now says `admin`.
    h.findMany.mockResolvedValue([groupBadgeRow("member")]);
    h.membershipFindUnique.mockResolvedValue({ role: "admin" });

    const out = await loadApprovedBadgeJwts(USER, CLIENT, SUB, ["badge-1"]);

    expect(out).toEqual(["reminted-vc"]);
    const sanitize = h.reMintVc.mock.calls[0]![2].sanitizeClaims;
    // Feeding the STORED claims (role: member) yields the LIVE role (admin).
    expect(sanitize({ group: "acme", role: "member", groupId: "grp-1" }, CRED_TYPE)).toEqual({
      group: "acme",
      role: "admin",
      groupId: "grp-1",
    });
  });

  it("allocates a per-RP status handle and stamps credentialStatus for a revocable badge", async () => {
    h.findMany.mockResolvedValue([{ ...groupBadgeRow("member"), statusAnchor: "gm:mem-1" }]);
    h.membershipFindUnique.mockResolvedValue({ role: "member" });
    h.allocateStatusEntry.mockResolvedValue({ listId: "list_x", bitIndex: 77 });

    const out = await loadApprovedBadgeJwts(USER, CLIENT, SUB, ["badge-1"]);

    expect(out).toEqual(["reminted-vc"]);
    // Per-RP allocation keyed on the FACT anchor + the requesting client.
    expect(h.allocateStatusEntry).toHaveBeenCalledWith({
      statusAnchor: "gm:mem-1",
      clientId: CLIENT,
    });
    // The disclosed VC carries the per-RP credentialStatus.
    expect(h.reMintVc.mock.calls[0]![2].credentialStatus).toEqual({
      id: "https://ministry.id/status/list_x#77",
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "77",
      statusListCredential: "https://ministry.id/status/list_x",
    });
  });

  it("does NOT allocate or stamp status for a non-revocable badge (no statusAnchor)", async () => {
    h.findMany.mockResolvedValue([groupBadgeRow("member")]); // no statusAnchor field
    h.membershipFindUnique.mockResolvedValue({ role: "member" });

    await loadApprovedBadgeJwts(USER, CLIENT, SUB, ["badge-1"]);

    expect(h.allocateStatusEntry).not.toHaveBeenCalled();
    expect(h.reMintVc.mock.calls[0]![2].credentialStatus).toBeUndefined();
  });

  it("fails closed (omit) on a malformed group badge with no groupId", async () => {
    h.findMany.mockResolvedValue([
      { ...groupBadgeRow("member"), attributes: { group: "acme", role: "member" } },
    ]);

    const out = await loadApprovedBadgeJwts(USER, CLIENT, SUB, ["badge-1"]);

    expect(out).toEqual([]);
    expect(h.reMintVc).not.toHaveBeenCalled();
    expect(h.audit).toHaveBeenCalledWith(
      USER,
      "oidc.badge_disclosure_omitted",
      expect.objectContaining({ badgeId: "badge-1" }),
    );
  });
});
