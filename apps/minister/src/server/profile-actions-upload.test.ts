import { beforeEach, describe, expect, it, vi } from "vitest";

// Exercises uploadAvatarAction end to end with every server-only dependency
// mocked (no DB, no session chain, no next/cache). The point is to prove:
//   - the blob write and the avatarUrl repoint happen in ONE interactive
//     $transaction (W1: no orphaned public blob against a stale avatarUrl);
//   - the persisted avatarUrl carries the OPAQUE publicId, never the userId
//     (W2: the disclosed picture claim can't leak the global account id);
//   - a non-image upload is still rejected by the magic-byte gate before any
//     write is attempted.

const upsert = vi.fn();
const userUpdate = vi.fn();
const transaction = vi.fn(async (cb: (tx: unknown) => unknown) =>
  cb({ userAvatar: { upsert }, user: { update: userUpdate } }),
);

vi.mock("@/lib/prisma", () => ({
  prisma: {
    $transaction: (...args: unknown[]) => transaction(...(args as [never])),
  },
}));
vi.mock("@/lib/session", () => ({
  getCurrentSession: () => Promise.resolve({ user: { id: "user-123" } }),
}));
vi.mock("@/lib/audit", () => ({ audit: () => Promise.resolve() }));
vi.mock("@/lib/oidc-config", () => ({ oidcIssuerUrl: () => "https://ministry.id" }));
vi.mock("next/cache", () => ({ revalidatePath: () => undefined }));

import { uploadAvatarAction } from "./profile-actions";

const PNG_BYTES = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01]);
const UPDATED_AT = new Date("2026-07-09T00:00:00.000Z");

function formWith(file: File | null, displayName = "Ada"): FormData {
  const fd = new FormData();
  fd.set("displayName", displayName);
  if (file) fd.set("file", file);
  return fd;
}

describe("uploadAvatarAction", () => {
  beforeEach(() => {
    upsert.mockReset();
    userUpdate.mockReset();
    transaction.mockClear();
    upsert.mockResolvedValue({ publicId: "opaque-handle-xyz", updatedAt: UPDATED_AT });
    userUpdate.mockResolvedValue({});
  });

  it("writes the blob and repoints avatarUrl inside a single interactive transaction", async () => {
    const file = new File([PNG_BYTES], "me.png", { type: "image/png" });
    const result = await uploadAvatarAction(formWith(file));

    expect(result).toEqual({ ok: true });
    // Exactly one interactive transaction, given a callback (not an array).
    expect(transaction).toHaveBeenCalledTimes(1);
    expect(typeof transaction.mock.calls[0]?.[0]).toBe("function");
    // Both writes ran on the transaction client.
    expect(upsert).toHaveBeenCalledTimes(1);
    expect(userUpdate).toHaveBeenCalledTimes(1);
  });

  it("generates an opaque publicId on create and persists the opaque serve URL", async () => {
    const file = new File([PNG_BYTES], "me.png", { type: "image/png" });
    await uploadAvatarAction(formWith(file));

    // The create branch carries a freshly generated, non-empty opaque publicId
    // that is NOT the userId.
    const createArg = upsert.mock.calls[0]?.[0] as {
      create: { publicId: string; userId: string; contentType: string };
    };
    expect(typeof createArg.create.publicId).toBe("string");
    expect(createArg.create.publicId.length).toBeGreaterThan(0);
    expect(createArg.create.publicId).not.toBe("user-123");
    expect(createArg.create.contentType).toBe("image/png");

    // The persisted avatarUrl uses the upserted publicId, never the userId path.
    const updateArg = userUpdate.mock.calls[0]?.[0] as { data: { avatarUrl: string } };
    expect(updateArg.data.avatarUrl).toBe(
      `https://ministry.id/api/avatars/opaque-handle-xyz?v=${UPDATED_AT.getTime()}`,
    );
    expect(updateArg.data.avatarUrl).not.toContain("/api/users/");
    expect(updateArg.data.avatarUrl).not.toContain("user-123");
  });

  it("rejects a non-image upload by magic bytes before any write", async () => {
    const notAnImage = new File([new Uint8Array([0x3c, 0x73, 0x76, 0x67])], "x.png", {
      type: "image/png",
    });
    const result = await uploadAvatarAction(formWith(notAnImage));

    expect(result).toHaveProperty("error");
    expect(transaction).not.toHaveBeenCalled();
    expect(upsert).not.toHaveBeenCalled();
  });

  it("returns an error (no write) when no file is chosen", async () => {
    const result = await uploadAvatarAction(formWith(null));
    expect(result).toHaveProperty("error");
    expect(transaction).not.toHaveBeenCalled();
  });
});
