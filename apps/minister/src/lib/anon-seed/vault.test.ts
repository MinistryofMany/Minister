import { beforeEach, describe, expect, it, vi } from "vitest";

import { encodeSeedToString, encodeSeedToWords } from "@minister/shared";

// The vault imports the anon-seed server actions; mock them so no env/prisma
// loads and so the tests can assert exactly what the vault would upload.
vi.mock("@/server/anon-seed-actions", () => ({
  getAnonSeedState: vi.fn(),
  getAnonPasskeyCredentialIds: vi.fn(),
  getSeedBlobs: vi.fn(),
  putSeedBlob: vi.fn(),
}));

import {
  getAnonPasskeyCredentialIds,
  getAnonSeedState,
  getSeedBlobs,
  putSeedBlob,
} from "@/server/anon-seed-actions";

import {
  ANON_FRAGMENT_PREFIX,
  buildAnonFragment,
  buildAnonRedirect,
  deriveAppSecret,
  enrollPasskeyBlob,
  isVaultReady,
  lockVault,
  markVaultActive,
  savePasswordToManager,
  unlockVault,
  unlockWithPasskey,
  unlockWithSeedInput,
} from "./vault";

// Spec §5.4 / §8.1 golden vectors: seed = ASCII "Ministry of Many".
const SEED_HEX = "4d696e6973747279206f66204d616e79";
const SEED = Uint8Array.from(Buffer.from(SEED_HEX, "hex"));
const SEED_STRING = "dk8QMNVR47r8d2rxXhHFFHLRTj5y";
const DEFORUM_SECRET_HEX = "a6a39187454acc287e62b9eaeabecef8c67bf08500fc53bd5e00912ab0f71a5e";
const DEFORUM_SECRET_B64URL = Buffer.from(DEFORUM_SECRET_HEX, "hex").toString("base64url");

const USER = "user-a";
const PRF_OUTPUT = new Uint8Array(32).fill(0x11);

const mocked = {
  getAnonSeedState: vi.mocked(getAnonSeedState),
  getAnonPasskeyCredentialIds: vi.mocked(getAnonPasskeyCredentialIds),
  getSeedBlobs: vi.mocked(getSeedBlobs),
  putSeedBlob: vi.mocked(putSeedBlob),
};

// A fake WebAuthn assertion carrying a PRF result — what the vault's
// dedicated get() consumes. Duck-typed exactly like the vault reads it.
function fakeAssertion(credentialId: string, prfOutput: Uint8Array | null) {
  return {
    id: credentialId,
    type: "public-key",
    getClientExtensionResults: () =>
      prfOutput === null ? {} : { prf: { results: { first: prfOutput.buffer.slice(0) } } },
  };
}

function stubNavigatorGet(assertion: unknown) {
  vi.stubGlobal("navigator", {
    credentials: { get: vi.fn(async () => assertion) },
  });
}

beforeEach(() => {
  lockVault();
  vi.unstubAllGlobals();
  vi.resetAllMocks();
});

describe("the seam: deriveAppSecret gating (I3, I4, multi-account check 15)", () => {
  it("refuses while locked", async () => {
    await expect(deriveAppSecret("deforum", USER)).rejects.toThrow(/locked/);
  });

  it("refuses before enrollment is ACTIVE (I3)", async () => {
    unlockVault(USER, SEED, { active: false });
    await expect(deriveAppSecret("deforum", USER)).rejects.toThrow(/not active/);
  });

  it("derives the spec 8.1 golden once unlocked and active", async () => {
    unlockVault(USER, SEED, { active: false });
    markVaultActive(USER);
    const secret = await deriveAppSecret("deforum", USER);
    expect(Buffer.from(secret).toString("hex")).toBe(DEFORUM_SECRET_HEX);
  });

  it("refuses another user's derivation while user A's seed is loaded", async () => {
    unlockVault(USER, SEED, { active: true });
    await expect(deriveAppSecret("deforum", "user-b")).rejects.toThrow(/locked/);
  });

  it("markVaultActive is a no-op for a different user", () => {
    unlockVault(USER, SEED, { active: false });
    markVaultActive("user-b");
    expect(isVaultReady(USER)).toBe(false);
  });

  it("lockVault drops the seed", async () => {
    unlockVault(USER, SEED, { active: true });
    lockVault();
    await expect(deriveAppSecret("deforum", USER)).rejects.toThrow(/locked/);
  });
});

describe("fragment building (spec 8.2 grammar)", () => {
  it("emits #minister_anon=v1.<43 base64url chars>", () => {
    const fragment = buildAnonFragment(Uint8Array.from(Buffer.from(DEFORUM_SECRET_HEX, "hex")));
    expect(fragment).toBe(ANON_FRAGMENT_PREFIX + DEFORUM_SECRET_B64URL);
    expect(fragment.slice(ANON_FRAGMENT_PREFIX.length)).toHaveLength(43);
  });

  it("rejects a secret that is not exactly 32 bytes", () => {
    expect(() => buildAnonFragment(new Uint8Array(16))).toThrow(/32 bytes/);
  });
});

describe("buildAnonRedirect: fail-open for login, fail-closed for identity (8.3)", () => {
  const REDIRECT = "https://rp.example/cb?code=abc&state=xyz";

  it("returns the plain URL when the vault is locked — never a made-up secret", async () => {
    await expect(buildAnonRedirect(REDIRECT, "deforum", USER)).resolves.toBe(REDIRECT);
  });

  it("returns the plain URL when enrollment is not active", async () => {
    unlockVault(USER, SEED, { active: false });
    await expect(buildAnonRedirect(REDIRECT, "deforum", USER)).resolves.toBe(REDIRECT);
  });

  it("appends the golden fragment when unlocked and active", async () => {
    unlockVault(USER, SEED, { active: true });
    await expect(buildAnonRedirect(REDIRECT, "deforum", USER)).resolves.toBe(
      REDIRECT + ANON_FRAGMENT_PREFIX + DEFORUM_SECRET_B64URL,
    );
  });

  it("returns the plain URL for a malformed app id", async () => {
    unlockVault(USER, SEED, { active: true });
    await expect(buildAnonRedirect(REDIRECT, "NOT A SLUG", USER)).resolves.toBe(REDIRECT);
  });
});

describe("L0/L2 entry: unlockWithSeedInput (spec 5.3 parser)", () => {
  it("unlocks from the canonical string", async () => {
    unlockWithSeedInput(USER, SEED_STRING);
    const secret = await deriveAppSecret("deforum", USER);
    expect(Buffer.from(secret).toString("hex")).toBe(DEFORUM_SECRET_HEX);
  });

  it("unlocks from the 12 words", async () => {
    unlockWithSeedInput(USER, encodeSeedToWords(SEED).join(" "));
    const secret = await deriveAppSecret("deforum", USER);
    expect(Buffer.from(secret).toString("hex")).toBe(DEFORUM_SECRET_HEX);
  });

  it("hard-rejects garbage and stays locked", async () => {
    expect(() => unlockWithSeedInput(USER, "not a key")).toThrow();
    await expect(deriveAppSecret("deforum", USER)).rejects.toThrow(/locked/);
  });
});

describe("L1 enroll: wraps client-side, uploads ciphertext only (I1, 7.1)", () => {
  it("uploads a blob that contains no codec form of the seed and round-trips through unlock", async () => {
    // Enroll: vault holds the seed, server says ACTIVE at epoch 1.
    unlockVault(USER, SEED, { active: true });
    mocked.getAnonSeedState.mockResolvedValue({
      ok: true,
      state: { status: "active", enrollmentEpoch: 1 },
    });
    mocked.getAnonPasskeyCredentialIds.mockResolvedValue({
      ok: true,
      credentialIds: ["cred-1"],
    });
    mocked.putSeedBlob.mockResolvedValue({ ok: true });
    stubNavigatorGet(fakeAssertion("cred-1", PRF_OUTPUT));

    const result = await enrollPasskeyBlob(USER);
    expect(result).toEqual({ ok: true, credentialId: "cred-1" });

    expect(mocked.putSeedBlob).toHaveBeenCalledTimes(1);
    const payload = mocked.putSeedBlob.mock.calls[0]![0];
    expect(Object.keys(payload).sort()).toEqual([
      "ciphertext",
      "credentialId",
      "iv",
      "wrapVersion",
    ]);
    // Exact transport sizes (32-byte GCM output, 12-byte IV).
    expect(Buffer.from(payload.ciphertext, "base64url")).toHaveLength(32);
    expect(Buffer.from(payload.iv, "base64url")).toHaveLength(12);
    // The assertable slice of I1: nothing uploaded contains the seed in any
    // encoding, nor the PRF output.
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain(SEED_STRING);
    expect(serialized).not.toContain(Buffer.from(SEED).toString("base64url"));
    expect(serialized).not.toContain(Buffer.from(SEED).toString("hex"));
    expect(serialized).not.toContain(Buffer.from(PRF_OUTPUT).toString("base64url"));

    // Unlock on a "fresh page": locked vault, blob served back at epoch 1.
    lockVault();
    mocked.getSeedBlobs.mockResolvedValue({
      ok: true,
      blobs: [
        {
          credentialId: "cred-1",
          ciphertext: payload.ciphertext,
          iv: payload.iv,
          wrapVersion: 1,
          enrollmentEpoch: 1,
        },
      ],
    });
    const unlock = await unlockWithPasskey(USER);
    expect(unlock).toEqual({ ok: true });
    const secret = await deriveAppSecret("deforum", USER);
    expect(Buffer.from(secret).toString("hex")).toBe(DEFORUM_SECRET_HEX);

    // Anti-rollback (I12): the same blob under a bumped epoch fails closed.
    lockVault();
    mocked.getSeedBlobs.mockResolvedValue({
      ok: true,
      blobs: [
        {
          credentialId: "cred-1",
          ciphertext: payload.ciphertext,
          iv: payload.iv,
          wrapVersion: 1,
          enrollmentEpoch: 2,
        },
      ],
    });
    const stale = await unlockWithPasskey(USER);
    expect(stale.ok).toBe(false);
    if (!stale.ok) expect(stale.reason).toBe("mismatch");
    expect(isVaultReady(USER)).toBe(false);
  });

  it("refuses to enroll before ACTIVE (I3)", async () => {
    unlockVault(USER, SEED, { active: false });
    mocked.getAnonSeedState.mockResolvedValue({
      ok: true,
      state: { status: "pending_backup", enrollmentEpoch: 1 },
    });
    const result = await enrollPasskeyBlob(USER);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("not-active");
    expect(mocked.putSeedBlob).not.toHaveBeenCalled();
  });

  it("degrades explicitly when the authenticator yields no PRF (I5)", async () => {
    unlockVault(USER, SEED, { active: true });
    mocked.getAnonSeedState.mockResolvedValue({
      ok: true,
      state: { status: "active", enrollmentEpoch: 1 },
    });
    mocked.getAnonPasskeyCredentialIds.mockResolvedValue({
      ok: true,
      credentialIds: ["cred-1"],
    });
    stubNavigatorGet(fakeAssertion("cred-1", null));
    const result = await enrollPasskeyBlob(USER);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("prf-unsupported");
    expect(mocked.putSeedBlob).not.toHaveBeenCalled();
  });
});

describe("L2 save (spec 7.2)", () => {
  it("reports unsupported outside a PasswordCredential browser (no window here)", async () => {
    unlockVault(USER, SEED, { active: true });
    await expect(savePasswordToManager(USER)).resolves.toBe("unsupported");
  });

  it("stores via navigator.credentials.store — the no-form path (I11)", async () => {
    unlockVault(USER, SEED, { active: true });
    const stored: Array<{ id: string; password: string }> = [];
    class FakePasswordCredential {
      type = "password";
      constructor(public init: { id: string; name?: string; password: string }) {}
    }
    vi.stubGlobal("window", { PasswordCredential: FakePasswordCredential });
    vi.stubGlobal("navigator", {
      credentials: {
        store: vi.fn(async (cred: FakePasswordCredential) => {
          stored.push({ id: cred.init.id, password: cred.init.password });
          return cred;
        }),
      },
    });
    await expect(savePasswordToManager(USER)).resolves.toBe("stored");
    expect(stored).toEqual([{ id: "anonymous-writing-key", password: encodeSeedToString(SEED) }]);
  });
});
