import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { HandleStepResult, IssuedBadge, Plugin } from "@minister/plugin-sdk";
import { loadIssuer, _resetIssuerCache, type Issuer } from "@minister/vc";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// Phase 3 regression: the wizard mint path driven END-TO-END through the REAL
// signet NullifierService backend (scripted in-memory Signet, no network) —
// proving that serializeMintWindow in wizard.ts and the advisory-lock release
// in signet-backend.ts together close the Case-A delete-vs-reissue dedup
// bypass ACROSS the Minister/Signet split, exactly as the interim backend's
// atomic conditional DELETE closes it in-database (wizard-discard.test.ts).
// Also pins: Signet-down at issuance → a MAPPED wizard error (retryable, not
// a thrown 500), no reservation leak, retry works; and the self-heal path —
// including the compensate-on-re-register-failure regression (a signed badge
// must never survive without a ledger entry).

const h = vi.hoisted(() => {
  // Select the signet backend BEFORE any module import runs; transport is
  // injected in beforeAll, the pin once the mock's key exists. PEMs are
  // inline so the config layer never touches the filesystem.
  process.env.MINISTER_NULLIFIER_BACKEND = "signet";
  process.env.MINISTER_SIGNET_URL = "https://signet.test";
  process.env.MINISTER_SIGNET_CLIENT_CERT =
    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
  process.env.MINISTER_SIGNET_CLIENT_KEY =
    "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----";
  process.env.MINISTER_SIGNET_CA_CERT =
    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";

  interface Row {
    [k: string]: unknown;
  }
  interface Store {
    user: Row[];
    badge: Row[];
    wizardSession: Row[];
    auditLog: Row[];
    eligibility: Row[];
  }
  const tables: Store = { user: [], badge: [], wizardSession: [], auditLog: [], eligibility: [] };
  let seq = 1;

  const matchesWhere = (row: Row, where?: Record<string, unknown>): boolean => {
    if (!where) return true;
    for (const [k, cond] of Object.entries(where)) {
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
      const r = tables[name].find((row) => matchesWhere(row, args.where));
      return r ? { ...r } : null;
    }),
    findFirst: vi.fn(async (args: { where: Record<string, unknown> }) => {
      const r = tables[name].find((row) => matchesWhere(row, args.where));
      return r ? { ...r } : null;
    }),
    findMany: vi.fn(async (args?: { where?: Record<string, unknown> }) =>
      tables[name].filter((row) => matchesWhere(row, args?.where)).map((r) => ({ ...r })),
    ),
    count: vi.fn(
      async (args?: { where?: Record<string, unknown> }) =>
        tables[name].filter((row) => matchesWhere(row, args?.where)).length,
    ),
    create: vi.fn(async (args: { data: Record<string, unknown> }) => {
      const row: Row = { ...args.data };
      if (row.id === undefined) row.id = `${name}_${seq++}`;
      if (name === "badge" && row.nullifierRef === undefined) row.nullifierRef = null;
      tables[name].push(row);
      return { ...row };
    }),
    update: vi.fn(
      async (args: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
        const r = tables[name].find((row) => matchesWhere(row, args.where));
        if (!r) throw Object.assign(new Error("not found"), { code: "P2025" });
        Object.assign(r, args.data);
        return { ...r };
      },
    ),
    updateMany: vi.fn(
      async (args: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
        let count = 0;
        for (const r of tables[name]) {
          if (matchesWhere(r, args.where)) {
            Object.assign(r, args.data);
            count++;
          }
        }
        return { count };
      },
    ),
    deleteMany: vi.fn(async (args: { where: Record<string, unknown> }) => {
      const before = tables[name].length;
      tables[name] = tables[name].filter((r) => !matchesWhere(r, args.where));
      return { count: before - tables[name].length };
    }),
  });

  // A REAL async mutex behind the advisory-lock emulation: $transaction hands
  // out a tx whose $queryRaw acquires the mutex keyed by the interpolated
  // lock string and releases it when the callback settles — the
  // pg_advisory_xact_lock lifetime. Liveness probes (`SELECT 1`) and
  // `SET LOCAL lock_timeout` are recognized and no-op (the fake tx never
  // times out). Transactions that never touch the lock (issueBadge's
  // insert-sign-update) just run their callback. The same fake serves as BOTH
  // the shared prisma client and the dedicated lock client (lock-client.ts) —
  // in production those are separate pools, but the lock semantics under test
  // are identical.
  const locks = new Map<string, Promise<void>>();
  async function acquire(key: string): Promise<() => void> {
    for (;;) {
      const holder = locks.get(key);
      if (!holder) break;
      await holder;
    }
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    locks.set(key, held);
    return () => {
      locks.delete(key);
      release();
    };
  }

  const prisma: Record<string, unknown> = {};
  prisma.$transaction = vi.fn(
    async (fn: (tx: unknown) => Promise<unknown>, _opts?: Record<string, unknown>) => {
      // Array, not a nullable local: TS cannot see the closure assignment.
      const held: Array<() => void> = [];
      const tx = Object.create(prisma) as Record<string, unknown>;
      tx.$executeRaw = async () => 0;
      tx.$queryRaw = async (strings: TemplateStringsArray, ...values: unknown[]) => {
        if (strings.join("").includes("pg_advisory_xact_lock")) {
          held.push(await acquire(String(values[0])));
        }
        return [];
      };
      try {
        return await fn(tx);
      } finally {
        for (const release of held) release();
      }
    },
  );
  for (const name of Object.keys(tables) as (keyof Store)[]) prisma[name] = makeModel(name);
  return { tables, prisma };
});

vi.mock("@/lib/prisma", () => ({ prisma: h.prisma }));
vi.mock("@/lib/nullifier/lock-client", () => ({ getLockClient: () => h.prisma }));
vi.mock("@/lib/issuer", () => ({ getIssuer: vi.fn() }));
vi.mock("@/lib/mailer", () => ({ sendMail: vi.fn().mockResolvedValue(undefined) }));
vi.mock("@/plugins/registry", () => ({ getPlugin: vi.fn() }));

import { getIssuer } from "@/lib/issuer";
import { nullifierService } from "@/lib/nullifier";
import { _setSignetTransportForTests, type SignetTransport } from "@/lib/nullifier/signet-backend";
import { MockSignet } from "@/lib/nullifier/signet-backend.testutil";
import { getPlugin } from "@/plugins/registry";
import { ISSUANCE_UNAVAILABLE_MESSAGE as UNAVAILABLE_MESSAGE, submitStep } from "@/server/wizard";

const ANCHOR = "778899001122";
const USER = "user_signet_race";

let tmpDir: string;
let issuer: Issuer;
let mock: MockSignet;

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

function seedSession(id: string): void {
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

const githubBadge = (): IssuedBadge => ({
  type: "oauth-account",
  attributes: { provider: "github", handle: "octocat" },
  claims: { provider: "github", handle: "octocat" },
  sybilAnchor: ANCHOR,
});

beforeAll(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), "minister-signet-race-"));
  _resetIssuerCache();
  issuer = await loadIssuer({ domain: "ministry.test", devKeyPath: join(tmpDir, "issuer.jwk") });
  vi.mocked(getIssuer).mockResolvedValue(issuer);
});

afterAll(async () => {
  _setSignetTransportForTests(null);
  _resetIssuerCache();
  await rm(tmpDir, { recursive: true, force: true });
});

beforeEach(async () => {
  for (const k of Object.keys(h.tables) as (keyof typeof h.tables)[]) h.tables[k] = [];
  h.tables.user.push({ id: USER, dedupHandle: "handle_A" });
  // Fresh Signet (empty ledger) per test; same frozen seed each time, so the
  // pinned key the default backend already fetch-verified stays valid.
  mock = await MockSignet.create(
    Buffer.from("4d494e49535445522d544553542d564543544f522d534545442d303030312121", "hex"),
  );
  process.env.MINISTER_SIGNET_DEDUP_PUBKEY = mock.publicKeyB64;
  _setSignetTransportForTests(mock.transport());
});

describe("wizard mint path through the REAL signet backend", () => {
  it("issues end-to-end: registers in the Signet ledger, persists the opaque ref, refuses a second owner", async () => {
    vi.mocked(getPlugin).mockReturnValue(fakePlugin([githubBadge()]));
    seedSession("ws1");
    const result = await submitStep("ws1", USER, "http://localhost:3000", { code: "x" });
    expect(result.kind).toBe("complete");

    expect(mock.entryCount()).toBe(1);
    const badge = h.tables.badge[0]!;
    expect(typeof badge.nullifierRef).toBe("string");
    expect(mock.hasRef(badge.nullifierRef as string)).toBe(true);
    // The raw anchor is nowhere in the Badge row.
    expect(JSON.stringify(badge.attributes)).not.toContain(ANCHOR);

    // One-credential-one-account across the split: a different owner is
    // refused with the user-facing message.
    h.tables.user[0]!.id = USER; // unchanged; second submit uses another user row
    h.tables.user.push({ id: "user_other", dedupHandle: "handle_B" });
    h.tables.wizardSession.push({
      id: "ws2",
      userId: "user_other",
      pluginId: "github",
      state: {
        currentStep: { id: "s", kind: "redirect", payload: { url: "x" } },
        data: { redirectUri: "x" },
      },
      completedAt: null,
      pendingToken: null,
      expiresAt: new Date(Date.now() + 60_000),
    });
    const second = await submitStep("ws2", "user_other", "http://localhost:3000", { code: "x" });
    expect(second.kind).toBe("error");
    if (second.kind !== "error") throw new Error("kind");
    expect(second.message).toBe(
      "This GitHub account is already linked to another Minister account.",
    );
    expect(mock.entryCount()).toBe(1);
  });

  // Case A re-driven against the signet backend's atomicity mechanism (build
  // plan Phase 3 item 4). Timeline: the re-issue holds the mint-window lock
  // across [B2 INSERT → probe]; the concurrent deleteBadge release — whose
  // stale sibling count decided to free E — fires DURING the window, blocks
  // on the same per-ref lock, and once inside sees B2 committed → skips the
  // Signet delete. Without the lock the release's Signet round trip would
  // land after the probe returned true: a freed entry under a live signed
  // badge — the exact bypass the interim conditional DELETE closes in-DB.
  it("Case A across the split: a release firing after the probe returned true cannot free the entry B2 references", async () => {
    // Account A already holds sibling badge B1 → ledger entry E.
    const first = await nullifierService.registerDedup({
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

    // Model the concurrent deleteBadge(B1): its one-shot sibling count (t4)
    // saw 0, its badge-row delete committed, and its post-commit release
    // fires exactly while the mint window is inside the probe (t6→t7). The
    // spy starts the release, WITHOUT awaiting it, then runs the real probe;
    // the release must still be pending when the window closes.
    let release: Promise<void> | null = null;
    let releaseSettledDuringWindow = false;
    // Capture the REAL probe before installing the spy so it can call through.
    const originalProbe = nullifierService.entryExistsForOwner.bind(nullifierService);
    const probeSpy = vi
      .spyOn(nullifierService, "entryExistsForOwner")
      .mockImplementationOnce(async (input) => {
        h.tables.badge = h.tables.badge.filter((b) => b.id !== "badge_sibling_B1");
        release = nullifierService.release({ entryRef: eRef, ownerHandle: "handle_A" }).then(() => {
          releaseSettledDuringWindow = true;
        });
        // Yield generously: an unserialized release would complete here and
        // free E before the probe reads it.
        for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
        return originalProbe(input);
      });

    vi.mocked(getPlugin).mockReturnValue(fakePlugin([githubBadge()]));
    seedSession("ws3");
    const result = await submitStep("ws3", USER, "http://localhost:3000", { code: "x" });
    probeSpy.mockRestore();
    expect(result.kind).toBe("complete");

    expect(release).not.toBeNull();
    expect(releaseSettledDuringWindow).toBe(false);
    await release;

    // E survives: the release's fresh in-lock sibling check saw B2. The new
    // badge references a live entry; no bypass.
    expect(mock.hasRef(eRef)).toBe(true);
    const b2 = h.tables.badge.find((b) => b.id !== "badge_sibling_B1")!;
    expect(b2.nullifierRef).toBe(eRef);
    const other = await nullifierService.registerDedup({
      anchor: ANCHOR,
      badgeType: "oauth-account",
      ownerHandle: "handle_C",
    });
    expect(other.status).toBe("taken");
  });

  it("Signet down at issuance: mapped wizard error (never a thrown 500), nothing persisted, retry succeeds", async () => {
    mock.downStatus = 503;
    vi.mocked(getPlugin).mockReturnValue(fakePlugin([githubBadge()]));
    seedSession("ws4");
    const result = await submitStep("ws4", USER, "http://localhost:3000", { code: "x" });
    // Surfaced through the wizard's error renderer as a retryable outcome,
    // not thrown into the generic server-action error boundary.
    expect(result).toEqual({ kind: "error", message: UNAVAILABLE_MESSAGE });
    // No badge, no ledger entry, session not completed — and a durable ops
    // trail for the outage.
    expect(h.tables.badge).toHaveLength(0);
    expect(mock.entryCount()).toBe(0);
    expect(h.tables.wizardSession[0]!.completedAt).toBeNull();
    expect(h.tables.auditLog.some((r) => r.action === "wizard.issuance_unavailable")).toBe(true);

    // Outage over → the retry completes cleanly.
    mock.downStatus = null;
    seedSession("ws5");
    const retry = await submitStep("ws5", USER, "http://localhost:3000", { code: "x" });
    expect(retry.kind).toBe("complete");
    expect(h.tables.badge).toHaveLength(1);
    expect(mock.entryCount()).toBe(1);
  });

  it("Signet failing between register and probe: batch rolls back with no reservation leak, retry succeeds", async () => {
    // Fail ONLY the probe (/prf/disclose) — the register succeeded, so a
    // naive abort would strand the fresh registration.
    const scripted = mock.transport();
    let failProbe = true;
    const flaky: SignetTransport = async (m, p, b) => {
      if (failProbe && p === "/prf/disclose") {
        return { status: 503, json: { error: "down", message: "scripted outage" } };
      }
      return scripted(m, p, b);
    };
    _setSignetTransportForTests(flaky);
    try {
      vi.mocked(getPlugin).mockReturnValue(fakePlugin([githubBadge()]));
      seedSession("ws6");
      const result = await submitStep("ws6", USER, "http://localhost:3000", { code: "x" });
      expect(result).toEqual({ kind: "error", message: UNAVAILABLE_MESSAGE });
      // compensateBatch deleted the badge AND released the fresh
      // registration: no orphan badge, no stranded ledger entry.
      expect(h.tables.badge).toHaveLength(0);
      expect(mock.entryCount()).toBe(0);

      failProbe = false;
      seedSession("ws7");
      const retry = await submitStep("ws7", USER, "http://localhost:3000", { code: "x" });
      expect(retry.kind).toBe("complete");
      expect(h.tables.badge).toHaveLength(1);
      expect(mock.entryCount()).toBe(1);
    } finally {
      _setSignetTransportForTests(mock.transport());
    }
  });

  // Self-heal happy path: a concurrent release freed the entry between
  // registerDedup's `already_yours`/`registered` and the probe. The probe
  // sees it gone; the runtime re-registers and repoints the badge (under the
  // per-ref lock on the NEW ref), completing cleanly.
  it("self-heals when the entry is released before the probe: re-registers and repoints the badge", async () => {
    const scripted = mock.transport();
    let vanishOnce = true;
    const racing: SignetTransport = async (m, p, b) => {
      if (vanishOnce && p === "/prf/disclose") {
        vanishOnce = false;
        // Emulate the concurrent release landing just before the probe: the
        // entry really is gone from the ledger when the probe looks.
        const req = b as { entry_ref: string; owner_handle: string };
        await scripted("POST", "/dedup/release", {
          entry_ref: req.entry_ref,
          owner_handle: req.owner_handle,
        });
      }
      return scripted(m, p, b);
    };
    _setSignetTransportForTests(racing);
    try {
      vi.mocked(getPlugin).mockReturnValue(fakePlugin([githubBadge()]));
      seedSession("ws8");
      const result = await submitStep("ws8", USER, "http://localhost:3000", { code: "x" });
      expect(result.kind).toBe("complete");
      // Exactly one badge, pointing at the re-registered (live) entry.
      expect(h.tables.badge).toHaveLength(1);
      const ref = h.tables.badge[0]!.nullifierRef as string;
      expect(mock.hasRef(ref)).toBe(true);
      expect(mock.entryCount()).toBe(1);
      // Dedup still holds against another account.
      const other = await nullifierService.registerDedup({
        anchor: ANCHOR,
        badgeType: "oauth-account",
        ownerHandle: "handle_B",
      });
      expect(other.status).toBe("taken");
    } finally {
      _setSignetTransportForTests(mock.transport());
    }
  });

  // The uncompensated-self-heal regression: probe=false (entry gone) and the
  // self-heal RE-REGISTER then fails (Signet 5xx — the expected outage shape
  // for a network backend). The whole batch must compensate: a signed badge
  // must NEVER survive with no ledger entry (that would let a second account
  // register the same credential — the Phase 1 dedup bypass, reopened).
  it("probe=false then re-register outage: whole batch compensates, no badge without a ledger entry, retry succeeds", async () => {
    const scripted = mock.transport();
    let probeSeen = false;
    let registerCalls = 0;
    const flaky: SignetTransport = async (m, p, b) => {
      if (!probeSeen && p === "/prf/disclose") {
        probeSeen = true;
        // The concurrent release freed the entry right before the probe.
        const req = b as { entry_ref: string; owner_handle: string };
        await scripted("POST", "/dedup/release", {
          entry_ref: req.entry_ref,
          owner_handle: req.owner_handle,
        });
        return scripted(m, p, b); // 404 → probe returns false
      }
      if (p === "/dedup/register") {
        registerCalls++;
        // First register (the mint) succeeds; the self-heal re-register
        // hits the outage.
        if (registerCalls >= 2) {
          return { status: 503, json: { error: "down", message: "scripted outage" } };
        }
      }
      return scripted(m, p, b);
    };
    _setSignetTransportForTests(flaky);
    try {
      vi.mocked(getPlugin).mockReturnValue(fakePlugin([githubBadge()]));
      seedSession("ws9");
      const result = await submitStep("ws9", USER, "http://localhost:3000", { code: "x" });
      expect(result).toEqual({ kind: "error", message: UNAVAILABLE_MESSAGE });
      // Fail-closed: no badge, no ledger entry, session retryable.
      expect(h.tables.badge).toHaveLength(0);
      expect(mock.entryCount()).toBe(0);
      expect(h.tables.wizardSession.find((s) => s.id === "ws9")!.completedAt).toBeNull();

      // Outage over → a clean retry issues end-to-end.
      _setSignetTransportForTests(mock.transport());
      seedSession("ws10");
      const retry = await submitStep("ws10", USER, "http://localhost:3000", { code: "x" });
      expect(retry.kind).toBe("complete");
      expect(h.tables.badge).toHaveLength(1);
      expect(mock.entryCount()).toBe(1);
    } finally {
      _setSignetTransportForTests(mock.transport());
    }
  });
});
