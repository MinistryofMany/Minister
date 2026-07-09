import type { WalletChain } from "@minister/shared";

// Best-effort wallet-age lookup against FIXED, keyless public explorers. The
// only outbound calls this plugin ever makes are the two below, to hardcoded
// hosts, with a STRICTLY validated address (0x-hex for ETH, base58/bech32 for
// BTC — see verify.ts) as the only interpolated value. There is never a
// user-controlled host and never a call back to the wallet itself, so this is
// not an SSRF surface; the address validation is the injection guard.
//
// Every function here is best-effort: any network, HTTP, or parse failure
// resolves to `null` (age simply skipped), never a throw that would fail the
// whole ownership flow.

const FETCH_TIMEOUT_MS = 8_000;

async function fetchJson(url: string): Promise<unknown | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) return null;
    return (await res.json()) as unknown;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// Blockscout: oldest tx first, one row. `result[0].timeStamp` is unix seconds
// (string). Returns the first-tx date, or null on any miss.
export function parseBlockscoutFirstTx(body: unknown): Date | null {
  if (typeof body !== "object" || body === null) return null;
  const result = (body as { result?: unknown }).result;
  if (!Array.isArray(result) || result.length === 0) return null;
  const first = result[0];
  if (typeof first !== "object" || first === null) return null;
  const ts = (first as { timeStamp?: unknown }).timeStamp;
  const seconds = typeof ts === "string" ? Number(ts) : typeof ts === "number" ? ts : NaN;
  if (!Number.isFinite(seconds) || seconds <= 0) return null;
  const d = new Date(seconds * 1000);
  return Number.isNaN(d.getTime()) ? null : d;
}

// mempool.space esplora returns confirmed txs newest-first, 25 per page. The
// oldest on the first page is a CONSERVATIVE lower bound on wallet age (a wallet
// with more history looks younger, never older), so we never over-claim age.
// Precise first-tx would require paginating to the chain tip — out of v1 scope.
export function parseEsploraOldestTx(body: unknown): Date | null {
  if (!Array.isArray(body) || body.length === 0) return null;
  let oldest: number | null = null;
  for (const tx of body) {
    if (typeof tx !== "object" || tx === null) continue;
    const status = (tx as { status?: unknown }).status;
    if (typeof status !== "object" || status === null) continue;
    const bt = (status as { block_time?: unknown }).block_time;
    if (typeof bt !== "number" || !Number.isFinite(bt) || bt <= 0) continue;
    if (oldest === null || bt < oldest) oldest = bt;
  }
  if (oldest === null) return null;
  const d = new Date(oldest * 1000);
  return Number.isNaN(d.getTime()) ? null : d;
}

// Resolve the wallet's first-transaction date, or null (best-effort). The
// address must already be validated/normalized by the caller.
export async function fetchWalletFirstTxDate(
  chain: WalletChain,
  normalizedAddress: string,
): Promise<Date | null> {
  if (chain === "ethereum") {
    const url =
      `https://eth.blockscout.com/api?module=account&action=txlist` +
      `&address=${normalizedAddress}&sort=asc&page=1&offset=1`;
    return parseBlockscoutFirstTx(await fetchJson(url));
  }
  const url = `https://mempool.space/api/address/${normalizedAddress}/txs/chain`;
  return parseEsploraOldestTx(await fetchJson(url));
}
