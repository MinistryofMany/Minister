import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadIssuer, _resetIssuerCache, type Issuer } from "@minister/vc";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// Email-plugin Sybil-anchor DISCARD regression (crypto-core Phase 5, items 1-2).
// Drives the REAL email-domain and email-exact plugins through the REAL
// issueBadgesAndComplete → issueBadge → issueVc signing path via submitStep,
// then string-scans every at-rest surface for the raw address. Non-vacuous: the
// signed vcJwt payload is base64url-decoded before scanning, and each case
// asserts a positive control (the domain, or the revealed address) is present in
// the signed VC so a broken mock can't pass an empty payload.

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

  const $executeRaw = vi.fn(async () => 0);

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
import { emailDomainPlugin } from "@/plugins/email-domain";
import { emailExactPlugin } from "@/plugins/email-exact";
import { getPlugin } from "@/plugins/registry";
import { submitStep } from "@/server/wizard";

const USER = "user_email_discard";

function decodedJwtPayload(jwt: unknown): string {
  if (typeof jwt !== "string") return "";
  const parts = jwt.split(".");
  if (parts.length < 2) return "";
  return Buffer.from(parts[1]!, "base64url").toString("utf8");
}

function seedMagicSession(id: string, pluginId: string, data: Record<string, unknown>): void {
  h.tables.wizardSession.push({
    id,
    userId: USER,
    pluginId,
    state: {
      currentStep: {
        id: "wait-magic-link",
        kind: "magic-link",
        payload: { sentTo: "hidden", expectedToken: "tok_12345678" },
      },
      data,
    },
    completedAt: null,
    pendingToken: "tok_12345678",
    expiresAt: new Date(Date.now() + 60_000),
  });
}

let tmpDir: string;
let issuer: Issuer;

beforeAll(async () => {
  process.env.OIDC_PAIRWISE_SECRET = "email-discard-test-secret-32-chars!!!";
  tmpDir = await mkdtemp(join(tmpdir(), "minister-email-discard-"));
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

describe("email-domain — anchor discarded, only the domain revealed", () => {
  // Distinctive local-part so the scan is meaningful; the domain is revealed by
  // design and is the positive control.
  const LOCAL = "scantarget";
  const DOMAIN = "discardprobe.example";
  const ADDRESS = `${LOCAL}@${DOMAIN}`;

  it("nullifies the address, reveals only the domain, and DISCARDS the address everywhere", async () => {
    vi.mocked(getPlugin).mockReturnValue(emailDomainPlugin);
    seedMagicSession("wd1", "email-domain", { domain: DOMAIN, email: ADDRESS });

    const result = await submitStep("wd1", USER, "http://localhost:3000", {
      token: "tok_12345678",
    });
    expect(result.kind).toBe("complete");

    // A ledger entry now exists (the address was nullified into a nullifierRef).
    expect(h.tables.nullifierEntry).toHaveLength(1);
    const badge = h.tables.badge[0]!;
    expect(badge.type).toBe("email-domain");
    expect(badge.nullifierRef).toBe(h.tables.nullifierEntry[0]!.id);

    // Positive control: the DOMAIN rides the signed VC (non-vacuous scan target).
    expect(decodedJwtPayload(badge.vcJwt)).toContain(DOMAIN);

    // The local part / full address appears in NO at-rest surface.
    expect(JSON.stringify(badge.attributes)).not.toContain(LOCAL);
    expect(decodedJwtPayload(badge.vcJwt)).not.toContain(LOCAL);
    expect(decodedJwtPayload(badge.vcJwt)).not.toContain(ADDRESS);
    expect(JSON.stringify(h.tables.auditLog)).not.toContain(LOCAL);
    const session = h.tables.wizardSession[0]!;
    expect(JSON.stringify(session.state)).not.toContain(LOCAL);
    expect(session.state).toEqual({ scrubbed: true });
    expect(session.completedAt).not.toBeNull();

    // Not in the ledger row either (only its HMAC is stored).
    expect(Buffer.from(h.tables.nullifierEntry[0]!.value as Uint8Array).toString()).not.toContain(
      LOCAL,
    );
  });

  it("refuses a second account with an EMAIL-worded taken error (not GitHub copy)", async () => {
    // Another account already holds this exact address under email-domain.
    const { interimBackend } = await import("@/lib/nullifier/interim");
    await interimBackend.registerDedup({
      anchor: ADDRESS,
      badgeType: "email-domain",
      ownerHandle: "other_owner",
    });

    vi.mocked(getPlugin).mockReturnValue(emailDomainPlugin);
    seedMagicSession("wd2", "email-domain", { domain: DOMAIN, email: ADDRESS });
    const result = await submitStep("wd2", USER, "http://localhost:3000", {
      token: "tok_12345678",
    });
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toBe(
      "This email address is already linked to another Minister account.",
    );
    // No badge minted; the pre-existing entry is untouched.
    expect(h.tables.badge).toHaveLength(0);
    expect(h.tables.nullifierEntry).toHaveLength(1);
    expect(h.tables.nullifierEntry[0]!.ownerHandle).toBe("other_owner");
  });
});

describe("email-domain — the continue step leaks NO pending token or address to the client", () => {
  const LOCAL = "clientleakprobe";
  const DOMAIN = "leakprobe.example";
  const ADDRESS = `${LOCAL}@${DOMAIN}`;

  it("returns a client-safe state from submitStep: expectedToken and data stripped, full state persisted", async () => {
    vi.mocked(getPlugin).mockReturnValue(emailDomainPlugin);
    // Seed the FORM step (pre-magic-link); submitting it sends the email and
    // transitions to the magic-link step.
    h.tables.wizardSession.push({
      id: "wf1",
      userId: USER,
      pluginId: "email-domain",
      state: {
        currentStep: {
          id: "collect-email",
          kind: "form",
          payload: { title: "Verify an email domain", fields: [] },
        },
        data: {},
      },
      completedAt: null,
      pendingToken: null,
      expiresAt: new Date(Date.now() + 60_000),
    });

    const result = await submitStep("wf1", USER, "http://localhost:3000", { email: ADDRESS });
    expect(result.kind).toBe("continue");
    if (result.kind !== "continue") throw new Error("kind");

    expect(result.state.currentStep.kind).toBe("magic-link");
    if (result.state.currentStep.kind !== "magic-link") throw new Error("kind");
    // capture-at-verify: the pending TOKEN (inbox-control proof) must not cross
    // the server-action wire. (sentTo legitimately echoes the address back to the
    // SAME browser that just typed it — that is display, not a token leak.)
    expect(result.state.currentStep.payload.expectedToken).toBeUndefined();
    // The server-side `data` accumulator (which carries the raw address) is
    // dropped entirely from the client copy.
    expect(result.state.data).toEqual({});
    expect(JSON.stringify(result.state.data)).not.toContain(LOCAL);

    // The PERSISTED row still holds the token (as pendingToken) and the raw
    // address (in data) so the emailed link can complete the flow.
    const row = h.tables.wizardSession.find((r) => r.id === "wf1")!;
    expect(typeof row.pendingToken).toBe("string");
    const persistedToken = row.pendingToken as string;
    expect(persistedToken.length).toBeGreaterThan(8);
    // The token that reached the DB must NOT appear anywhere in the client copy.
    expect(JSON.stringify(result.state)).not.toContain(persistedToken);
    expect(JSON.stringify((row.state as { data: unknown }).data)).toContain(ADDRESS);
  });
});

describe("email-exact — address revealed BY DESIGN, but scrubbed from state + audit", () => {
  const LOCAL = "scanexact";
  const DOMAIN = "exactprobe.example";
  const ADDRESS = `${LOCAL}@${DOMAIN}`;

  it("reveals the address in the VC (by design), nullifies it, and keeps it out of state + audit", async () => {
    vi.mocked(getPlugin).mockReturnValue(emailExactPlugin);
    seedMagicSession("we1", "email-exact", { email: ADDRESS });

    const result = await submitStep("we1", USER, "http://localhost:3000", {
      token: "tok_12345678",
    });
    expect(result.kind).toBe("complete");

    expect(h.tables.nullifierEntry).toHaveLength(1);
    const badge = h.tables.badge[0]!;
    expect(badge.type).toBe("email-exact");
    expect(badge.nullifierRef).toBe(h.tables.nullifierEntry[0]!.id);

    // Revealed by design: the address IS the claim, signed into the VC.
    expect(decodedJwtPayload(badge.vcJwt)).toContain(ADDRESS);
    expect(JSON.stringify(badge.attributes)).toContain(ADDRESS);

    // But the AuditLog and the persisted wizard state must NOT carry it.
    expect(JSON.stringify(h.tables.auditLog)).not.toContain(LOCAL);
    const session = h.tables.wizardSession[0]!;
    expect(JSON.stringify(session.state)).not.toContain(LOCAL);
    expect(session.state).toEqual({ scrubbed: true });

    // Not in the ledger row (only its HMAC).
    expect(Buffer.from(h.tables.nullifierEntry[0]!.value as Uint8Array).toString()).not.toContain(
      LOCAL,
    );
  });

  it("holding BOTH email badges for one mailbox does not self-collide (distinct namespaces)", async () => {
    // email-domain issues first (registers anchor under type email-domain)...
    vi.mocked(getPlugin).mockReturnValue(emailDomainPlugin);
    seedMagicSession("we2a", "email-domain", { domain: DOMAIN, email: ADDRESS });
    const r1 = await submitStep("we2a", USER, "http://localhost:3000", { token: "tok_12345678" });
    expect(r1.kind).toBe("complete");

    // ...then email-exact for the SAME mailbox: a DIFFERENT badge_type, so the
    // dedup namespace differs and this must NOT be refused as `taken`.
    vi.mocked(getPlugin).mockReturnValue(emailExactPlugin);
    seedMagicSession("we2b", "email-exact", { email: ADDRESS });
    const r2 = await submitStep("we2b", USER, "http://localhost:3000", { token: "tok_12345678" });
    expect(r2.kind).toBe("complete");

    // Two distinct ledger entries, two badges.
    expect(h.tables.nullifierEntry).toHaveLength(2);
    expect(h.tables.badge).toHaveLength(2);
    expect(h.tables.badge[0]!.nullifierRef).not.toBe(h.tables.badge[1]!.nullifierRef);
  });
});
