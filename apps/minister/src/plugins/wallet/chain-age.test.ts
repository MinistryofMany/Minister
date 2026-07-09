import { afterEach, describe, expect, it, vi } from "vitest";

import { fetchWalletFirstTxDate, parseBlockscoutFirstTx, parseEsploraOldestTx } from "./chain-age";

describe("parseBlockscoutFirstTx", () => {
  it("reads the first tx timestamp (unix seconds string)", () => {
    const d = parseBlockscoutFirstTx({ status: "1", result: [{ timeStamp: "1577836800" }] });
    expect(d?.toISOString()).toBe("2020-01-01T00:00:00.000Z");
  });

  it("accepts a numeric timestamp", () => {
    const d = parseBlockscoutFirstTx({ result: [{ timeStamp: 1577836800 }] });
    expect(d?.toISOString()).toBe("2020-01-01T00:00:00.000Z");
  });

  it("returns null for an empty or malformed body", () => {
    expect(parseBlockscoutFirstTx({ result: [] })).toBeNull();
    expect(parseBlockscoutFirstTx({ result: "nope" })).toBeNull();
    expect(parseBlockscoutFirstTx(null)).toBeNull();
    expect(parseBlockscoutFirstTx({ result: [{ timeStamp: "0" }] })).toBeNull();
  });
});

describe("parseEsploraOldestTx", () => {
  it("returns the oldest block_time across the page (conservative lower bound)", () => {
    const d = parseEsploraOldestTx([
      { status: { block_time: 1700000000 } },
      { status: { block_time: 1577836800 } },
      { status: { block_time: 1650000000 } },
    ]);
    expect(d?.toISOString()).toBe("2020-01-01T00:00:00.000Z");
  });

  it("skips unconfirmed / malformed entries", () => {
    const d = parseEsploraOldestTx([
      { status: { confirmed: false } },
      { status: { block_time: 1577836800 } },
    ]);
    expect(d?.toISOString()).toBe("2020-01-01T00:00:00.000Z");
  });

  it("returns null for an empty or non-array body", () => {
    expect(parseEsploraOldestTx([])).toBeNull();
    expect(parseEsploraOldestTx({})).toBeNull();
    expect(parseEsploraOldestTx(null)).toBeNull();
  });
});

describe("fetchWalletFirstTxDate", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("calls the fixed Blockscout host for Ethereum with the address in the query", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      expect(url).toContain("https://eth.blockscout.com/api");
      expect(url).toContain("address=0x" + "a".repeat(40));
      return new Response(JSON.stringify({ result: [{ timeStamp: "1577836800" }] }), {
        status: 200,
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const d = await fetchWalletFirstTxDate("ethereum", "0x" + "a".repeat(40));
    expect(d?.toISOString()).toBe("2020-01-01T00:00:00.000Z");
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("calls the fixed mempool.space host for Bitcoin with the address in the path", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      expect(url).toBe(
        "https://mempool.space/api/address/1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV/txs/chain",
      );
      return new Response(JSON.stringify([{ status: { block_time: 1577836800 } }]), {
        status: 200,
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const d = await fetchWalletFirstTxDate("bitcoin", "1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV");
    expect(d?.toISOString()).toBe("2020-01-01T00:00:00.000Z");
  });

  it("returns null (never throws) on a network error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      }),
    );
    await expect(fetchWalletFirstTxDate("ethereum", "0x" + "a".repeat(40))).resolves.toBeNull();
  });

  it("returns null (never throws) on a non-200 response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("nope", { status: 503 })),
    );
    await expect(
      fetchWalletFirstTxDate("bitcoin", "1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV"),
    ).resolves.toBeNull();
  });
});
