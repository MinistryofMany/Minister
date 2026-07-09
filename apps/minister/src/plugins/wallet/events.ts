import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { OnchainEvent } from "@minister/shared";

// On-chain event registry: maps an event id to the set of (lowercased)
// Ethereum addresses that took part. Structured as a registry so more curated
// lists drop in later — add a loader here and the plugin's event check picks it
// up with no other change.
//
// The address sets are the ONLY place a wallet address is compared for event
// membership; the address is never persisted, logged, or disclosed — only the
// event id (the badge claim) is.

// Parsed CSV rows: `from_address,total_eth_deposits,num_deposits,<unnamed>`.
// We keep only the first column (the depositing address). Lowercased + deduped.
function parseAddressColumn(csv: string): Set<string> {
  const out = new Set<string>();
  const lines = csv.split(/\r?\n/u);
  // Skip the header row (index 0: `from_address,...`).
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const comma = line.indexOf(",");
    const first = comma === -1 ? line : line.slice(0, comma);
    const addr = first.trim().toLowerCase();
    // Only keep well-formed 0x-addresses; ignore any stray/blank cells so a
    // malformed row can never poison the membership set.
    if (/^0x[0-9a-f]{40}$/u.test(addr)) out.add(addr);
  }
  return out;
}

// Provenance: a snapshot of the unique addresses that sent deposits to the ETH2
// beacon-chain deposit contract, provided as `Beacon Depositors -
// unique_addresses_beacon_chain.csv` and committed under this plugin. Its sha256
// is pinned in events.test.ts so an accidental edit or a poisoned row fails CI.
//
// Loaded ONCE, memoized on first membership check. Deferred (not a top-level
// side effect) so importing the plugin registry never does file I/O — the read
// happens only when an Ethereum ownership proof is actually being checked, and
// only the first time. cwd is the app root (apps/minister) under dev, test, and
// `next build`.
const DEPOSITORS_CSV = join(process.cwd(), "src/plugins/wallet/data/beacon-genesis-depositors.csv");

let eth2GenesisDepositors: Set<string> | null = null;
function loadEth2GenesisDepositors(): Set<string> {
  if (eth2GenesisDepositors === null) {
    try {
      eth2GenesisDepositors = parseAddressColumn(readFileSync(DEPOSITORS_CSV, "utf8"));
    } catch (err) {
      // Fail SOFT: a missing/unreadable list must never crash issuance AFTER a
      // valid signature — it just means no on-chain event badge this run. Memoize
      // the empty set so we do not re-stat on every check, and emit an ops signal
      // (no user data here, only the fact the file did not load).
      console.warn(
        `[wallet] beacon-genesis-depositors.csv did not load (${
          err instanceof Error ? err.message : String(err)
        }); on-chain event badges are disabled until it is present.`,
      );
      eth2GenesisDepositors = new Set<string>();
    }
  }
  return eth2GenesisDepositors;
}

// Registry of event id -> membership predicate. Bitcoin has no event today, so
// the predicate is Ethereum-only for now; a future BTC event just adds an entry
// keyed on a lowercased-address set of its own.
const ETH_EVENT_SETS: Record<OnchainEvent, () => Set<string>> = {
  "eth2-genesis-depositor": loadEth2GenesisDepositors,
};

// Every event id whose set is checked for a given normalized ETH address. v1
// returns at most one ("eth2-genesis-depositor"); the shape allows several.
export function ethOnchainEventsFor(normalizedEthAddress: string): OnchainEvent[] {
  // Defensive: the sets are lowercased, and the plugin already passes the
  // lowercased anchor, but lowercasing here too means a mis-cased caller can
  // never silently miss a real depositor.
  const addr = normalizedEthAddress.toLowerCase();
  const hits: OnchainEvent[] = [];
  for (const [event, load] of Object.entries(ETH_EVENT_SETS) as Array<
    [OnchainEvent, () => Set<string>]
  >) {
    if (load().has(addr)) hits.push(event);
  }
  return hits;
}
