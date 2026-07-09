import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { HandleStepResult, IssuedBadge, Plugin } from "@minister/plugin-sdk";
import { loadIssuer, _resetIssuerCache, type Issuer } from "@minister/vc";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// Wizard-runtime Sybil-anchor DISCARD + SCRUB regression (crypto-core Phase 1,
// item 4/10). Exercises the REAL issueBadgesAndComplete → issueBadge → issueVc
// signing path via submitStep with a fake anchor-emitting plugin, then
// string-scans every at-rest surface (Badge row + signed VC, AuditLog metadata,
// wizard-session state) for the raw anchor. This is the standing regression for
// ANY future plugin that emits `sybilAnchor`.

const h = vi.hoisted(() => {
  interface Row {
    [k: string]: unknown;
  }
  interface Store {
    user: Row[];
    badge: Row[];
    wizardSession: Row[];
    auditLog: Row[];
    eligibility: Row[];
    nullifierEntry: Row[];
  }
  const tables: Store = {
    user: [],
    badge: [],
    wizardSession: [],
    auditLog: [],
    eligibility: [],
    nullifierEntry: [],
  };
  let seq = 1;
  const p2002 = () => Object.assign(new Error("Unique constraint failed"), { code: "P2002" });
  const hex = (v: unknown) => Buffer.from(v as Uint8Array).toString("hex");

  const matchesWhere = (row: Row, where?: Record<string, unknown>): boolean => {
    if (!where) return true;
    for (const [k, cond] of Object.entries(where)) {
      if (k === "value" && cond instanceof Uint8Array) {
        if (hex(row.value) !== hex(cond)) return false;
        continue;
      }
      if (cond !== null && typeof cond === "object" && !(cond instanceof Date)) {
        const c = cond as Record<string, unknown>;
        if ("in" in c) {
          if (!(c.in as unknown[]).includes(row[k])) return false;
          continue;
        }
        if ("not" in c) {
          if (row[k] === c.not) return false;
          continue;
        }
      }
      if (row[k] !== cond) return false;
    }
    return true;
  };

  const makeModel = (name: keyof Store) => ({
    findUnique: vi.fn(async (args: { where: Record<string, unknown> }) => {
      const r = tables[name]!.find((row) => matchesWhere(row, args.where));
      return r ? { ...r } : null;
    }),
    findFirst: vi.fn(async (args: { where: Record<string, unknown> }) => {
      const r = tables[name]!.find((row) => matchesWhere(row, args.where));
      return r ? { ...r } : null;
    }),
    findMany: vi.fn(async (args?: { where?: Record<string, unknown> }) =>
      tables[name]!.filter((row) => matchesWhere(row, args?.where)).map((r) => ({ ...r })),
    ),
    create: vi.fn(async (args: { data: Record<string, unknown> }) => {
      if (
        name === "nullifierEntry" &&
        tables[name]!.some((e) => hex(e.value) === hex(args.data.value))
      ) {
        throw p2002();
      }
      const row: Row = { ...args.data };
      if (row.id === undefined) row.id = `${name}_${seq++}`;
      if (name === "badge" && row.nullifierRef === undefined) row.nullifierRef = null;
      tables[name]!.push(row);
      return { ...row };
    }),
    update: vi.fn(
      async (args: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
        const r = tables[name]!.find((row) => matchesWhere(row, args.where));
        if (!r) throw Object.assign(new Error("not found"), { code: "P2025" });
        Object.assign(r, args.data);
        return { ...r };
      },
    ),
    updateMany: vi.fn(
      async (args: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
        let count = 0;
        for (const r of tables[name]!) {
          if (matchesWhere(r, args.where)) {
            Object.assign(r, args.data);
            count++;
          }
        }
        return { count };
      },
    ),
    deleteMany: vi.fn(async (args: { where: Record<string, unknown> }) => {
      const before = tables[name]!.length;
      tables[name] = tables[name]!.filter((r) => !matchesWhere(r, args.where));
      return { count: before - tables[name]!.length };
    }),
  });

  // Emulates ONLY the interim release's atomic conditional DELETE
  // (lib/nullifier/interim.ts): entry deleted iff id+ownerHandle match AND no
  // Badge row references it — one atomic step here exactly as it is one
  // statement in Postgres. Shape-asserted so a query change must consciously
  // update this emulation, not silently pass.
  const $executeRaw = vi.fn(async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const sql = strings.raw.join("?").replace(/\s+/g, " ").trim();
    const isConditionalRelease =
      sql.startsWith('DELETE FROM "NullifierEntry"') &&
      sql.includes('NOT EXISTS (SELECT 1 FROM "Badge" WHERE "nullifierRef" = ?') &&
      values.length === 3;
    if (!isConditionalRelease) {
      throw new Error(`wizard-discard prisma mock: unrecognized raw query: ${sql}`);
    }
    const [entryRef, ownerHandle] = values as [string, string, string];
    if (tables.badge.some((b) => b.nullifierRef === entryRef)) return 0;
    const before = tables.nullifierEntry.length;
    tables.nullifierEntry = tables.nullifierEntry.filter(
      (e) => !(e.id === entryRef && e.ownerHandle === ownerHandle),
    );
    return before - tables.nullifierEntry.length;
  });

  const prisma: Record<string, unknown> = {
    $transaction: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => fn(prisma)),
    $executeRaw,
  };
  for (const name of Object.keys(tables) as (keyof Store)[]) prisma[name] = makeModel(name);
  return { tables, prisma };
});

vi.mock("@/lib/prisma", () => ({ prisma: h.prisma }));
vi.mock("@/lib/issuer", () => ({ getIssuer: vi.fn() }));
vi.mock("@/lib/mailer", () => ({ sendMail: vi.fn().mockResolvedValue(undefined) }));
vi.mock("@/plugins/registry", () => ({ getPlugin: vi.fn() }));

import { getIssuer } from "@/lib/issuer";
import { nullifierService } from "@/lib/nullifier";
import { getPlugin } from "@/plugins/registry";
import { submitStep } from "@/server/wizard";

const ANCHOR = "998877665544"; // a distinctive github numeric id to scan for
const USER = "user_wiz";

// A signed VC is a JWT whose payload is base64url — a raw substring scan of the
// compact JWT would NEVER see the anchor even if it leaked (the encoded form of
// "998877665544" is not that substring). Decode the payload segment before
// scanning, so the "covers the signed vcJwt" claim is real and not vacuous.
function decodedJwtPayload(jwt: unknown): string {
  if (typeof jwt !== "string") return "";
  const parts = jwt.split(".");
  if (parts.length < 2) return "";
  return Buffer.from(parts[1]!, "base64url").toString("utf8");
}

let tmpDir: string;
let issuer: Issuer;

function fakePlugin(badges: IssuedBadge[]): Plugin {
  return {
    manifest: {
      id: "github",
      name: "GitHub",
      description: "",
      badgeTypes: ["oauth-account"],
      requiresExtension: false,
    },
    startWizard: vi.fn(),
    handleStep: vi.fn(async (): Promise<HandleStepResult> => ({ kind: "complete", badges })),
  };
}

function seedSession(id = "ws1"): void {
  h.tables.wizardSession.push({
    id,
    userId: USER,
    pluginId: "github",
    state: {
      currentStep: { id: "s", kind: "redirect", payload: { url: "x" } },
      data: { redirectUri: "x" },
    },
    completedAt: null,
    pendingToken: null,
    expiresAt: new Date(Date.now() + 60_000),
  });
}

beforeAll(async () => {
  process.env.OIDC_PAIRWISE_SECRET = "wizard-discard-test-secret-32-chars!!";
  tmpDir = await mkdtemp(join(tmpdir(), "minister-wiz-discard-"));
  _resetIssuerCache();
  issuer = await loadIssuer({ domain: "ministry.test", devKeyPath: join(tmpDir, "issuer.jwk") });
  vi.mocked(getIssuer).mockResolvedValue(issuer);
});

afterAll(async () => {
  _resetIssuerCache();
  await rm(tmpDir, { recursive: true, force: true });
  delete process.env.OIDC_PAIRWISE_SECRET;
});

beforeEach(() => {
  for (const k of Object.keys(h.tables) as (keyof typeof h.tables)[]) h.tables[k] = [];
  h.tables.user.push({ id: USER, dedupHandle: null });
});

const githubBadge = (): IssuedBadge => ({
  type: "oauth-account",
  attributes: { provider: "github", handle: "octocat" },
  claims: { provider: "github", handle: "octocat" },
  sybilAnchor: ANCHOR,
});

describe("wizard runtime — Sybil-anchor discard + scrub", () => {
  it("nullifies the anchor, persists a nullifierRef, and DISCARDS the raw anchor everywhere", async () => {
    vi.mocked(getPlugin).mockReturnValue(fakePlugin([githubBadge()]));
    seedSession();

    const result = await submitStep("ws1", USER, "http://localhost:3000", { code: "x" });
    expect(result.kind).toBe("complete");

    // A ledger entry now exists, owned by the user's freshly-minted handle.
    expect(h.tables.nullifierEntry).toHaveLength(1);
    const user = h.tables.user[0]!;
    expect(user.dedupHandle).toEqual(expect.any(String));
    expect(h.tables.nullifierEntry[0]!.ownerHandle).toBe(user.dedupHandle);

    // The Badge row carries the opaque ref, NOT the anchor.
    const badge = h.tables.badge[0]!;
    expect(badge.nullifierRef).toBe(h.tables.nullifierEntry[0]!.id);

    // STRING-SCAN every at-rest surface for the raw anchor — it must appear in NONE.
    // Badge.attributes is plain JSON; the signed vcJwt is base64url, so decode its
    // payload before scanning (a raw JSON.stringify(badge) scan of the JWT column
    // would be vacuous — the encoded form hides the substring).
    expect(JSON.stringify(badge.attributes)).not.toContain(ANCHOR); // attributes (plain JSON)
    expect(decodedJwtPayload(badge.vcJwt)).not.toContain(ANCHOR); // DECODED signed VC payload
    // Positive control (S-1): the REVEALED handle DOES ride the signed payload,
    // so the `not.toContain(ANCHOR)` above is a real check on a populated VC —
    // a broken mock that emitted an empty/unsigned payload would fail here.
    expect(decodedJwtPayload(badge.vcJwt)).toContain("octocat");
    expect(JSON.stringify(h.tables.auditLog)).not.toContain(ANCHOR); // audit metadata
    const session = h.tables.wizardSession[0]!;
    expect(JSON.stringify(session.state)).not.toContain(ANCHOR); // scrubbed state.data
    // Scrub-on-completion: the persisted state was overwritten.
    expect(session.state).toEqual({ scrubbed: true });
    expect(session.completedAt).not.toBeNull();

    // The anchor is nowhere in the ledger row either (only its HMAC is stored).
    expect(
      JSON.stringify(Buffer.from(h.tables.nullifierEntry[0]!.value as Uint8Array).toString()),
    ).not.toContain(ANCHOR);
  });

  it("refuses issuance with a user-facing error when the credential is already linked (taken)", async () => {
    // Pre-seed the ledger with the same credential under ANOTHER owner.
    const { interimBackend } = await import("@/lib/nullifier/interim");
    await interimBackend.registerDedup({
      anchor: ANCHOR,
      badgeType: "oauth-account",
      ownerHandle: "someone_else",
    });

    vi.mocked(getPlugin).mockReturnValue(fakePlugin([githubBadge()]));
    seedSession("ws2");

    const result = await submitStep("ws2", USER, "http://localhost:3000", { code: "x" });
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toBe(
      "This GitHub account is already linked to another Minister account.",
    );

    // No badge minted; the pre-existing entry is untouched.
    expect(h.tables.badge).toHaveLength(0);
    expect(h.tables.nullifierEntry).toHaveLength(1);
    expect(h.tables.nullifierEntry[0]!.ownerHandle).toBe("someone_else");
  });

  it("re-issuing the same credential from the same account is idempotent (already_yours)", async () => {
    vi.mocked(getPlugin).mockReturnValue(fakePlugin([githubBadge()]));
    seedSession("ws3");
    await submitStep("ws3", USER, "http://localhost:3000", { code: "x" });

    seedSession("ws4");
    const again = await submitStep("ws4", USER, "http://localhost:3000", { code: "x" });
    expect(again.kind).toBe("complete");
    // Same single ledger entry — no duplicate.
    expect(h.tables.nullifierEntry).toHaveLength(1);
    // Two badges, both pointing at the SAME ref.
    expect(h.tables.badge).toHaveLength(2);
    expect(h.tables.badge[0]!.nullifierRef).toBe(h.tables.badge[1]!.nullifierRef);
  });

  // Finding 5 — the value-based leak scan must not substring-false-positive.
  it("issues a legit account-age badge whose numeric claim shares the id's digits", async () => {
    // github id "60" collides with the account-age bucket olderThanMonths:60 as
    // a SUBSTRING of the serialized JSON — the old scan false-refused this user.
    const accountAgeBadge: IssuedBadge = {
      type: "account-age",
      attributes: { provider: "github", olderThanMonths: 60 },
      claims: { provider: "github", olderThanMonths: 60 },
      sybilAnchor: "60",
    };
    vi.mocked(getPlugin).mockReturnValue(fakePlugin([accountAgeBadge]));
    seedSession("ws5");

    const result = await submitStep("ws5", USER, "http://localhost:3000", { code: "x" });
    // Issues fine — the numeric claim 60 is not the string anchor "60".
    expect(result.kind).toBe("complete");
    expect(h.tables.badge).toHaveLength(1);
    expect(h.tables.badge[0]!.nullifierRef).toBe(h.tables.nullifierEntry[0]!.id);
  });

  it("still refuses when the raw anchor VALUE really is copied into attributes", async () => {
    // A real leak: the anchor string appears verbatim as an attribute value.
    const leakyBadge: IssuedBadge = {
      type: "oauth-account",
      attributes: { provider: "github", handle: "octocat", leaked: "60" },
      claims: { provider: "github", handle: "octocat" },
      sybilAnchor: "60",
    };
    vi.mocked(getPlugin).mockReturnValue(fakePlugin([leakyBadge]));
    seedSession("ws6");

    await expect(submitStep("ws6", USER, "http://localhost:3000", { code: "x" })).rejects.toThrow(
      /leaked a Sybil anchor/,
    );
    // Fail-closed: nothing minted, nothing left in the ledger.
    expect(h.tables.badge).toHaveLength(0);
    expect(h.tables.nullifierEntry).toHaveLength(0);
  });

  // FIX 5 — an HN user literally named "hackernews" makes claims.provider equal
  // the anchor. The `provider` field is a fixed plugin slug, never an anchor-leak
  // vector, so it must be exempt from the value guard — else the account-age badge
  // (which carries `provider` but has no revealsAnchor) is wrongly refused,
  // denying that user every HN badge. Availability edge case, must not fire.
  it("issues an account-age badge when the provider slug equals the anchor", async () => {
    const anchorEqualsProvider: IssuedBadge = {
      type: "account-age",
      attributes: { provider: "hackernews", olderThanMonths: 24 },
      claims: { provider: "hackernews", olderThanMonths: 24 },
      sybilAnchor: "hackernews",
    };
    vi.mocked(getPlugin).mockReturnValue(fakePlugin([anchorEqualsProvider]));
    seedSession("ws-hn");

    const result = await submitStep("ws-hn", USER, "http://localhost:3000", { code: "x" });
    expect(result.kind).toBe("complete");
    expect(h.tables.badge).toHaveLength(1);
    expect(h.tables.badge[0]!.nullifierRef).toBe(h.tables.nullifierEntry[0]!.id);
  });

  // The provider exemption must not blind the guard to a REAL leak that also
  // carries a matching provider slug: the anchor copied into any OTHER field
  // still fails closed.
  it("still refuses a real leak into a non-provider field even when provider matches", async () => {
    const leakyWithProvider: IssuedBadge = {
      type: "account-age",
      attributes: { provider: "hackernews", olderThanMonths: 24, leaked: "hackernews" },
      claims: { provider: "hackernews", olderThanMonths: 24 },
      sybilAnchor: "hackernews",
    };
    vi.mocked(getPlugin).mockReturnValue(fakePlugin([leakyWithProvider]));
    seedSession("ws-hn-leak");

    await expect(
      submitStep("ws-hn-leak", USER, "http://localhost:3000", { code: "x" }),
    ).rejects.toThrow(/leaked a Sybil anchor/);
    expect(h.tables.badge).toHaveLength(0);
    expect(h.tables.nullifierEntry).toHaveLength(0);
  });

  // Finding 1 — the delete-vs-reissue TOCTOU. Mint-side re-validation must
  // self-heal when a concurrent deleteBadge of the last sibling releases the
  // entry in the window between this re-issue's `already_yours` and its lagging
  // INSERT — never leaving two live entries (or a bypass) for one credential.
  it("self-heals when a concurrent delete releases the entry after the re-issue insert", async () => {
    // Deterministic owner handle so the interleaving is legible.
    h.tables.user[0]!.dedupHandle = "handle_A";

    // Account A already holds a sibling badge for this credential → entry E.
    const { interimBackend } = await import("@/lib/nullifier/interim");
    const first = await interimBackend.registerDedup({
      anchor: ANCHOR,
      badgeType: "oauth-account",
      ownerHandle: "handle_A",
    });
    if (first.status !== "registered") throw new Error("setup: expected a fresh registration");
    const eRef = first.entryRef;
    h.tables.badge.push({
      id: "badge_sibling_B1",
      userId: USER,
      type: "oauth-account",
      nullifierRef: eRef,
      vcJwt: "sibling",
      completedAt: null,
    });

    // Model the concurrent deleteBadge(B1): in the window between B2's INSERT
    // and this mint-side re-validation, the delete sees a sibling count of 0
    // (B2 not yet visible), deletes B1, and RELEASES E. Fire it exactly once,
    // at the re-validation probe for this badge.
    const spy = vi
      .spyOn(nullifierService, "entryExistsForOwner")
      .mockImplementationOnce(async () => {
        h.tables.badge = h.tables.badge.filter((b) => b.id !== "badge_sibling_B1");
        h.tables.nullifierEntry = h.tables.nullifierEntry.filter((e) => e.id !== eRef);
        return false; // E is gone underneath us
      });

    try {
      vi.mocked(getPlugin).mockReturnValue(fakePlugin([githubBadge()]));
      seedSession("ws7");
      const result = await submitStep("ws7", USER, "http://localhost:3000", { code: "x" });
      expect(result.kind).toBe("complete");
    } finally {
      spy.mockRestore();
    }

    // Self-healed: EXACTLY ONE ledger entry (the re-registered E'), owned by A —
    // never two live entries for one credential, never zero.
    expect(h.tables.nullifierEntry).toHaveLength(1);
    const healed = h.tables.nullifierEntry[0]!;
    expect(healed.ownerHandle).toBe("handle_A");
    // The freshly minted badge points at the healed entry, not the dangling ref.
    const mintedBadge = h.tables.badge.find((b) => b.id !== "badge_sibling_B1");
    expect(mintedBadge!.nullifierRef).toBe(healed.id);
    expect(mintedBadge!.nullifierRef).not.toBe(eRef);

    // No bypass: a DIFFERENT account cannot now register the same credential —
    // the healed entry still holds it.
    const other = await interimBackend.registerDedup({
      anchor: ANCHOR,
      badgeType: "oauth-account",
      ownerHandle: "handle_C",
    });
    expect(other.status).toBe("taken");
  });

  // Case A — the ordering the probe CANNOT see: the release fires AFTER the
  // mint-side re-validation returned true. Audit timeline: t4 the concurrent
  // deleteBadge(B1) counts siblings → 0 (B2's INSERT not yet committed) and
  // decides to release; t5 the re-issue commits B2 referencing E; t6 the mint
  // probe sees E present → true → no self-heal; t7 the delete's post-commit
  // release fires. A plain owner-checked deleteMany at t7 frees E under the
  // live signed B2 — dedup bypass. The atomic conditional release must no-op
  // at t7 because B2 references E. This test FAILS against the plain
  // deleteMany release and passes only with the conditional DELETE.
  it("Case A — a release firing AFTER the probe returned true cannot free the entry B2 references", async () => {
    h.tables.user[0]!.dedupHandle = "handle_A";

    // Account A holds sibling badge B1 → ledger entry E.
    const { interimBackend } = await import("@/lib/nullifier/interim");
    const first = await interimBackend.registerDedup({
      anchor: ANCHOR,
      badgeType: "oauth-account",
      ownerHandle: "handle_A",
    });
    if (first.status !== "registered") throw new Error("setup: expected a fresh registration");
    const eRef = first.entryRef;
    h.tables.badge.push({
      id: "badge_sibling_B1",
      userId: USER,
      type: "oauth-account",
      nullifierRef: eRef,
      vcJwt: "sibling",
    });

    // t5 + t6: the re-issue mints B2 (registerDedup → already_yours E) and the
    // REAL probe runs — E is present (the release has not fired yet) → true →
    // no self-heal. The spy keeps the real implementation; it only pins that
    // the probe really returned true, i.e. this is the probe-BEFORE-release
    // ordering, not the already-tested release-BEFORE-probe one.
    const probeSpy = vi.spyOn(nullifierService, "entryExistsForOwner");
    try {
      vi.mocked(getPlugin).mockReturnValue(fakePlugin([githubBadge()]));
      seedSession("ws8");
      const result = await submitStep("ws8", USER, "http://localhost:3000", { code: "x" });
      expect(result.kind).toBe("complete");
      expect(probeSpy).toHaveBeenCalledTimes(1);
      await expect(probeSpy.mock.results[0]!.value).resolves.toBe(true);
    } finally {
      probeSpy.mockRestore();
    }
    const mintedB2 = h.tables.badge.find((b) => b.id !== "badge_sibling_B1")!;
    expect(mintedB2.nullifierRef).toBe(eRef);

    // t7 (with t4's stale decision): B1's row delete has committed and the
    // deleteBadge release — gated only by the one-shot count taken back at t4
    // — fires NOW, through the real backend.
    h.tables.badge = h.tables.badge.filter((b) => b.id !== "badge_sibling_B1");
    await interimBackend.release({ entryRef: eRef, ownerHandle: "handle_A" });

    // E survives: the conditional DELETE saw B2 referencing it and no-op'd.
    expect(h.tables.nullifierEntry).toHaveLength(1);
    expect(h.tables.nullifierEntry[0]!.id).toBe(eRef);
    expect(mintedB2.nullifierRef).toBe(eRef);

    // No bypass: a second account registering the same anchor is refused.
    const other = await interimBackend.registerDedup({
      anchor: ANCHOR,
      badgeType: "oauth-account",
      ownerHandle: "handle_C",
    });
    expect(other.status).toBe("taken");
  });

  // W-1 — the compensateBatch analogue of Case A. A batch registers the anchor
  // FRESH (→ freshRegs), then aborts mid-batch; its compensating release of the
  // fresh registration is unconditional bookkeeping-wise, but a concurrent
  // SAME-USER batch can have gotten `already_yours` against that entry and
  // committed a live badge B2 pointing at it before the release fires. The
  // release must no-op on the referenced entry. Fails against the plain
  // deleteMany release; passes with the conditional DELETE.
  it("W-1 — compensateBatch cannot free an entry a concurrent same-user batch's badge references", async () => {
    h.tables.user[0]!.dedupHandle = "handle_A";
    const { interimBackend } = await import("@/lib/nullifier/interim");

    // Batch: badge 1 registers ANCHOR fresh and mints; badge 2 aborts the
    // batch (unknown type throws inside issueBadge, before any insert).
    const badBadge: IssuedBadge = { type: "not-a-real-type", attributes: {}, claims: {} };
    vi.mocked(getPlugin).mockReturnValue(fakePlugin([githubBadge(), badBadge]));
    seedSession("ws9");

    // Model the concurrent same-user batch: its `already_yours` badge B2
    // commits in the window between this batch's fresh registration of E and
    // the compensating release. Inject at compensateBatch's own-badge cleanup
    // (the last write before its releases run) — wrap the base implementation,
    // then land B2 referencing E.
    const badgeDeleteMany = (h.prisma as { badge: { deleteMany: ReturnType<typeof vi.fn> } }).badge
      .deleteMany;
    const base = badgeDeleteMany.getMockImplementation();
    if (!base) throw new Error("setup: badge.deleteMany has no base implementation");
    badgeDeleteMany.mockImplementationOnce(async (args: { where: Record<string, unknown> }) => {
      const res = await base(args);
      const entry = h.tables.nullifierEntry[0];
      if (!entry) throw new Error("setup: expected the batch's fresh registration to exist");
      h.tables.badge.push({
        id: "badge_concurrent_B2",
        userId: USER,
        type: "oauth-account",
        nullifierRef: entry.id,
        vcJwt: "concurrent",
      });
      return res;
    });

    await expect(submitStep("ws9", USER, "http://localhost:3000", { code: "x" })).rejects.toThrow(
      /unknown badge type/,
    );

    // The batch's own badge was rolled back; only the concurrent B2 remains.
    expect(h.tables.badge).toHaveLength(1);
    expect(h.tables.badge[0]!.id).toBe("badge_concurrent_B2");
    // E survives the compensating release — B2 references it.
    expect(h.tables.nullifierEntry).toHaveLength(1);
    expect(h.tables.badge[0]!.nullifierRef).toBe(h.tables.nullifierEntry[0]!.id);

    // No bypass: the credential is still held against a different account.
    const other = await interimBackend.registerDedup({
      anchor: ANCHOR,
      badgeType: "oauth-account",
      ownerHandle: "handle_C",
    });
    expect(other.status).toBe("taken");
  });
});
