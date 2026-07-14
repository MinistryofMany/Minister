import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AdapterAuthenticator } from "next-auth/adapters";

import { CREDENTIAL_QUARANTINE_MS } from "@/lib/assurance";

// Prove the bootstrap-count race is closed structurally: the count that
// decides bootstrap-active vs quarantined and the insert that acts on it run
// inside ONE prisma.$transaction, behind a per-user advisory lock taken
// FIRST. Prisma is mocked — the $transaction double invokes the callback with
// a tx client that records call order — so the ordering and per-user lock key
// are asserted without a live DB.

const h = vi.hoisted(() => {
  const order: string[] = [];
  let createdData: Record<string, unknown> | null = null;
  let countReturns = 0;
  const tx = {
    $executeRaw: vi.fn(async (..._args: unknown[]) => {
      order.push("lock");
      return 1;
    }),
    authenticator: {
      count: vi.fn(async () => {
        order.push("count");
        return countReturns;
      }),
      create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
        order.push("create");
        createdData = data;
        return data;
      }),
    },
  };
  return {
    order,
    tx,
    setCount: (n: number) => {
      countReturns = n;
    },
    getCreatedData: () => createdData,
    prisma: {
      $transaction: vi.fn(async (fn: (c: typeof tx) => Promise<unknown>) => fn(tx)),
    },
  };
});

vi.mock("@/lib/prisma", () => ({ prisma: h.prisma }));

import { insertPasskeyWithLifecycle } from "@/lib/passkey-enroll";

const baseData = (userId: string): AdapterAuthenticator => ({
  userId,
  credentialID: "cred-1",
  providerAccountId: "paa-1",
  credentialPublicKey: "pk",
  counter: 0,
  credentialDeviceType: "singleDevice",
  credentialBackedUp: false,
});

beforeEach(() => {
  h.order.length = 0;
  h.prisma.$transaction.mockClear();
  h.tx.$executeRaw.mockClear();
  h.tx.authenticator.count.mockClear();
  h.tx.authenticator.create.mockClear();
});

describe("insertPasskeyWithLifecycle", () => {
  it("takes the advisory lock, then counts, then creates — all in one transaction", async () => {
    h.setCount(0);
    await insertPasskeyWithLifecycle(baseData("user-a"));

    expect(h.prisma.$transaction).toHaveBeenCalledTimes(1);
    // Lock is acquired BEFORE the count that decides the lifecycle — otherwise
    // a concurrent insert could slip between count and create.
    expect(h.order).toEqual(["lock", "count", "create"]);
  });

  it("keys the advisory lock per user", async () => {
    h.setCount(0);
    await insertPasskeyWithLifecycle(baseData("user-xyz"));

    // Tagged-template values: [templateStrings, ...values]. The single value
    // is the namespaced, per-user lock key.
    const lockArgs = h.tx.$executeRaw.mock.calls[0];
    expect(lockArgs?.[1]).toBe("minister:passkey:bootstrap:user-xyz");
  });

  it("stamps the FIRST passkey (count 0) active immediately — the bootstrap", async () => {
    h.setCount(0);
    const { existing } = await insertPasskeyWithLifecycle(baseData("user-a"));

    expect(existing).toBe(0);
    const data = h.getCreatedData();
    expect(data?.status).toBe("active");
    expect(data?.quarantinedUntil).toBeNull();
  });

  it("quarantines a subsequent passkey (count 1) for the full cooldown", async () => {
    const now = Date.now();
    h.setCount(1);
    const { existing } = await insertPasskeyWithLifecycle(baseData("user-a"));

    expect(existing).toBe(1);
    const data = h.getCreatedData();
    expect(data?.status).toBe("quarantined");
    const until = data?.quarantinedUntil as Date;
    expect(until).toBeInstanceOf(Date);
    // ~72h ahead (loose bound to avoid clock-flake on the boundary).
    expect(until.getTime()).toBeGreaterThanOrEqual(now + CREDENTIAL_QUARANTINE_MS - 5000);
  });
});
