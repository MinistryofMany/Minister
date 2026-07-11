import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// requireAuthRecency / requireAal are PURE guards over the passed session —
// they read no DB. session.ts imports `@/auth` and `@/lib/prisma` at module
// scope (for the DB-backed session loaders we don't exercise here); stub both
// so the module loads without pulling in NextAuth / a live Prisma client.
vi.mock("@/auth", () => ({ auth: vi.fn() }));
vi.mock("@/lib/prisma", () => ({ prisma: {} }));

import type { Session } from "next-auth";

import { requireAuthRecency, StepUpRequiredError } from "./session";

// Pin the clock so window-edge assertions are deterministic (the guard reads
// Date.now() internally; without a fixed clock the boundary case could flake).
const NOW_MS = 1_700_000_000_000;
const NOW_SECS = Math.floor(NOW_MS / 1000);
const MAX = 600;

function sessionAt(authTime: number | undefined, aal = 2): Session {
  return { user: { id: "u1" }, aal, auth_time: authTime } as Session;
}

describe("requireAuthRecency", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW_MS);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("passes for a fresh authentication within the window", () => {
    expect(() => requireAuthRecency(sessionAt(NOW_SECS - 60), MAX)).not.toThrow();
  });

  it("passes at exactly the window edge (age == maxAgeSecs)", () => {
    expect(() => requireAuthRecency(sessionAt(NOW_SECS - MAX), MAX)).not.toThrow();
  });

  it("throws StepUpRequiredError one second past the window", () => {
    expect(() => requireAuthRecency(sessionAt(NOW_SECS - MAX - 1), MAX)).toThrow(
      StepUpRequiredError,
    );
  });

  it("throws StepUpRequiredError when auth_time is missing (fail closed)", () => {
    expect(() => requireAuthRecency(sessionAt(undefined), MAX)).toThrow(StepUpRequiredError);
  });

  it("throws StepUpRequiredError for a null session (fail closed)", () => {
    expect(() => requireAuthRecency(null, MAX)).toThrow(StepUpRequiredError);
  });

  it("requires AAL2 and surfaces the session's current AAL on the error", () => {
    try {
      requireAuthRecency(sessionAt(undefined, 1), MAX);
      throw new Error("expected requireAuthRecency to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(StepUpRequiredError);
      expect((err as StepUpRequiredError).requiredAal).toBe(2);
      expect((err as StepUpRequiredError).currentAal).toBe(1);
    }
  });

  it("treats a null session as AAL0 on the thrown error", () => {
    try {
      requireAuthRecency(null, MAX);
      throw new Error("expected requireAuthRecency to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(StepUpRequiredError);
      expect((err as StepUpRequiredError).currentAal).toBe(0);
    }
  });
});
