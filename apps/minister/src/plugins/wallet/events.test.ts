import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { ethOnchainEventsFor } from "./events";

// A known address from the committed depositor CSV, and one that is definitely
// not in it. The CSV is read the same way the module does (cwd = apps/minister
// under vitest) so the test pins the real parsed set, not a mock.
const CSV = join(process.cwd(), "src/plugins/wallet/data/beacon-genesis-depositors.csv");
const firstDataLine = readFileSync(CSV, "utf8").split(/\r?\n/u)[1] ?? "";
const KNOWN_DEPOSITOR = (firstDataLine.split(",")[0] ?? "").trim().toLowerCase();

describe("ethOnchainEventsFor", () => {
  it("reports eth2-genesis-depositor for an address in the set", () => {
    expect(KNOWN_DEPOSITOR).toMatch(/^0x[0-9a-f]{40}$/u);
    expect(ethOnchainEventsFor(KNOWN_DEPOSITOR)).toEqual(["eth2-genesis-depositor"]);
  });

  it("is case-insensitive on the input (set is lowercased)", () => {
    expect(ethOnchainEventsFor(KNOWN_DEPOSITOR.toUpperCase().replace("0X", "0x"))).toEqual([
      "eth2-genesis-depositor",
    ]);
  });

  it("reports no events for an address not in any set", () => {
    expect(ethOnchainEventsFor("0x" + "0".repeat(40))).toEqual([]);
  });

  it("loads the full depositor set (deduped, all well-formed)", () => {
    // Every well-formed row lands in the set; membership works for a large list.
    const total = readFileSync(CSV, "utf8")
      .split(/\r?\n/u)
      .slice(1)
      .filter((l) => /^0x[0-9a-f]{40}$/u.test((l.split(",")[0] ?? "").trim().toLowerCase()));
    expect(total.length).toBeGreaterThan(2000);
  });
});

describe("depositor CSV integrity", () => {
  it("matches the pinned sha256 (a changed or poisoned list fails CI)", () => {
    // This badge grants provable "took part in eth2 genesis" status, so the
    // membership set is security-relevant: pin its content hash so no row can be
    // silently added, removed, or altered without a reviewed, deliberate update.
    const hash = createHash("sha256").update(readFileSync(CSV)).digest("hex");
    expect(hash).toBe("51ce4cc29e87f94395e5dccc0dff9f7d12ca239010256cf301f37e982eb631ba");
  });
});
