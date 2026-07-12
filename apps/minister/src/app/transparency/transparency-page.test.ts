import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// The page is a .tsx server component compiled with the classic JSX runtime
// (React.createElement), so React must be in global scope for its render to run.
Object.assign(globalThis, { React });

// S2: the PUBLIC transparency page must render only PUBLISHED cohort defs. This
// test renders the server component with a fully-mocked prisma and asserts the
// cohortStatDef query is scoped to `where: { published: true }` — an unpublished
// (draft/internal) def can never reach the world-readable page.

const h = vi.hoisted(() => ({
  db: {
    badgeWeight: { findMany: vi.fn(async () => []) },
    sybilCategory: { findMany: vi.fn(async () => []) },
    sybilBucketConfig: { findUnique: vi.fn(async () => null) },
    statsRun: { findUnique: vi.fn(async () => null) },
    badgeStat: { findMany: vi.fn(async () => []) },
    cohortStatDef: {
      findMany: vi.fn((_args?: { where?: { published?: boolean } }) => Promise.resolve([])),
    },
  },
}));

vi.mock("@/lib/prisma", () => ({ prisma: h.db }));

import TransparencyPage from "@/app/transparency/page";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("public transparency page — cohort visibility", () => {
  it("queries ONLY published cohort defs", async () => {
    await TransparencyPage();
    expect(h.db.cohortStatDef.findMany).toHaveBeenCalledTimes(1);
    const arg = h.db.cohortStatDef.findMany.mock.calls[0]?.[0];
    expect(arg?.where).toEqual({ published: true });
  });
});
