import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock the Prisma client the route reads from — no live DB. The route reads
// userAvatar.findUnique twice: a metadata-only read (contentType + updatedAt)
// then, on a cache miss, a blob read (data). The mock inspects the requested
// `select` to answer each read.
const findUnique = vi.fn();
vi.mock("@/lib/prisma", () => ({
  prisma: { userAvatar: { findUnique: (...args: unknown[]) => findUnique(...args) } },
}));

import { GET } from "./route";

function context(publicId: string) {
  return { params: Promise.resolve({ publicId }) };
}

const PNG_BYTES = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01]);
const UPDATED_AT = new Date("2026-07-09T00:00:00.000Z");
const ETAG = `"${UPDATED_AT.getTime()}"`;
const PUBLIC_ID = "aVeryOpaqueRandomHandle";

// Answer the two-step read: a `select` asking for `data` is the blob read; any
// other select is the metadata read. `row` supplies the stored values; a null
// `row` means the avatar does not exist (both reads return null).
function withRow(row: { contentType: string; updatedAt: Date; data: Buffer } | null) {
  findUnique.mockImplementation((args: { select?: Record<string, boolean> }) => {
    if (row === null) return Promise.resolve(null);
    if (args.select?.data) return Promise.resolve({ data: row.data });
    return Promise.resolve({ contentType: row.contentType, updatedAt: row.updatedAt });
  });
}

function req(url: string, headers?: Record<string, string>) {
  return new Request(url, headers ? { headers } : undefined);
}

describe("GET /api/avatars/[publicId]", () => {
  beforeEach(() => {
    findUnique.mockReset();
  });

  it("404s when no avatar exists for that publicId", async () => {
    withRow(null);
    const res = await GET(req("https://ministry.id/api/avatars/missing"), context("missing"));
    expect(res.status).toBe(404);
  });

  it("404s (does not serve) when the stored type is not an allowed image type", async () => {
    withRow({
      contentType: "image/svg+xml",
      updatedAt: UPDATED_AT,
      data: Buffer.from([0x3c, 0x73, 0x76, 0x67]),
    });
    const res = await GET(req(`https://ministry.id/api/avatars/${PUBLIC_ID}`), context(PUBLIC_ID));
    expect(res.status).toBe(404);
  });

  it("serves the stored bytes with the hardening headers and a moderate cache", async () => {
    withRow({ contentType: "image/png", updatedAt: UPDATED_AT, data: PNG_BYTES });
    const res = await GET(req(`https://ministry.id/api/avatars/${PUBLIC_ID}`), context(PUBLIC_ID));

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/png");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(res.headers.get("Content-Disposition")).toBe("inline");
    expect(res.headers.get("Content-Security-Policy")).toBe("default-src 'none'; sandbox");
    expect(res.headers.get("ETag")).toBe(ETAG);

    const cacheControl = res.headers.get("Cache-Control") ?? "";
    expect(cacheControl).toContain("max-age=3600");
    expect(cacheControl).toContain("must-revalidate");
    // A deleted photo must NOT linger for a year: never immutable.
    expect(cacheControl).not.toContain("immutable");

    const body = new Uint8Array(await res.arrayBuffer());
    expect(Array.from(body)).toEqual(Array.from(PNG_BYTES));
  });

  it("returns 304 (no body, no blob read) when If-None-Match matches the ETag", async () => {
    withRow({ contentType: "image/png", updatedAt: UPDATED_AT, data: PNG_BYTES });
    const res = await GET(
      req(`https://ministry.id/api/avatars/${PUBLIC_ID}`, { "If-None-Match": ETAG }),
      context(PUBLIC_ID),
    );

    expect(res.status).toBe(304);
    expect(res.headers.get("ETag")).toBe(ETAG);
    expect((await res.arrayBuffer()).byteLength).toBe(0);
    // The blob (select: { data }) was never read — only the metadata read ran.
    const blobReads = findUnique.mock.calls.filter(
      (c) => (c[0] as { select?: { data?: boolean } }).select?.data,
    );
    expect(blobReads).toHaveLength(0);
  });

  it("returns 304 regardless of the ?v= query when the ETag matches", async () => {
    withRow({ contentType: "image/png", updatedAt: UPDATED_AT, data: PNG_BYTES });
    const res = await GET(
      req(`https://ministry.id/api/avatars/${PUBLIC_ID}?v=some-random-value`, {
        "If-None-Match": ETAG,
      }),
      context(PUBLIC_ID),
    );
    expect(res.status).toBe(304);
  });

  it("serves a full 200 when If-None-Match is stale (photo was replaced)", async () => {
    withRow({ contentType: "image/png", updatedAt: UPDATED_AT, data: PNG_BYTES });
    const res = await GET(
      req(`https://ministry.id/api/avatars/${PUBLIC_ID}`, { "If-None-Match": '"999"' }),
      context(PUBLIC_ID),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("ETag")).toBe(ETAG);
  });

  it("looks up only by the requested opaque publicId (no userId in the query)", async () => {
    withRow(null);
    await GET(req("https://ministry.id/api/avatars/target-handle"), context("target-handle"));
    expect(findUnique).toHaveBeenCalledWith(
      expect.objectContaining({ where: { publicId: "target-handle" } }),
    );
  });

  it("404s if the row vanishes between the metadata read and the blob read", async () => {
    // First (metadata) read succeeds; the row is then deleted, so the blob read
    // returns null. The route must 404, not throw.
    findUnique
      .mockResolvedValueOnce({ contentType: "image/png", updatedAt: UPDATED_AT })
      .mockResolvedValueOnce(null);
    const res = await GET(req(`https://ministry.id/api/avatars/${PUBLIC_ID}`), context(PUBLIC_ID));
    expect(res.status).toBe(404);
  });
});
