import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock the Prisma client the route reads from — no live DB. Only userAvatar
// .findUnique is exercised here.
const findUnique = vi.fn();
vi.mock("@/lib/prisma", () => ({
  prisma: { userAvatar: { findUnique: (...args: unknown[]) => findUnique(...args) } },
}));

import { GET } from "./route";

function context(userId: string) {
  return { params: Promise.resolve({ userId }) };
}

const PNG_BYTES = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01]);
const UPDATED_AT = new Date("2026-07-09T00:00:00.000Z");
const VERSION = UPDATED_AT.getTime().toString();

describe("GET /api/users/[userId]/avatar", () => {
  beforeEach(() => {
    findUnique.mockReset();
  });

  it("404s when the user has no uploaded avatar", async () => {
    findUnique.mockResolvedValue(null);
    const res = await GET(new Request("https://ministry.id/api/users/u1/avatar"), context("u1"));
    expect(res.status).toBe(404);
  });

  it("404s (does not serve) when the stored type is not an allowed image type", async () => {
    findUnique.mockResolvedValue({
      data: Buffer.from([0x3c, 0x73, 0x76, 0x67]),
      contentType: "image/svg+xml",
      updatedAt: UPDATED_AT,
    });
    const res = await GET(new Request("https://ministry.id/api/users/u1/avatar"), context("u1"));
    expect(res.status).toBe(404);
  });

  it("serves the stored bytes with the hardening headers", async () => {
    findUnique.mockResolvedValue({
      data: PNG_BYTES,
      contentType: "image/png",
      updatedAt: UPDATED_AT,
    });
    const res = await GET(new Request("https://ministry.id/api/users/u1/avatar"), context("u1"));

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/png");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(res.headers.get("Content-Disposition")).toBe("inline");
    expect(res.headers.get("Cache-Control")).toContain("public");

    const body = new Uint8Array(await res.arrayBuffer());
    expect(Array.from(body)).toEqual(Array.from(PNG_BYTES));
  });

  it("marks the current version immutable and a stale/absent version non-cacheable", async () => {
    findUnique.mockResolvedValue({
      data: PNG_BYTES,
      contentType: "image/png",
      updatedAt: UPDATED_AT,
    });

    const fresh = await GET(
      new Request(`https://ministry.id/api/users/u1/avatar?v=${VERSION}`),
      context("u1"),
    );
    expect(fresh.headers.get("Cache-Control")).toContain("immutable");

    findUnique.mockResolvedValue({
      data: PNG_BYTES,
      contentType: "image/png",
      updatedAt: UPDATED_AT,
    });
    const stale = await GET(
      new Request("https://ministry.id/api/users/u1/avatar?v=1"),
      context("u1"),
    );
    expect(stale.headers.get("Cache-Control")).toContain("must-revalidate");
  });

  it("looks up only the requested userId (no cross-user leak)", async () => {
    findUnique.mockResolvedValue(null);
    await GET(new Request("https://ministry.id/api/users/target/avatar"), context("target"));
    expect(findUnique).toHaveBeenCalledWith(
      expect.objectContaining({ where: { userId: "target" } }),
    );
  });
});
