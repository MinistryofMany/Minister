import type { Metadata } from "next";

import { getBadgeType } from "@minister/shared";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { prisma } from "@/lib/prisma";
import { buildPublicCohortRow, buildPublicTypeRows } from "@/lib/transparency-view";

// PUBLIC, read-only, no auth gate (phase-2 impl brief §6). World-readable, so the
// three privacy layers (allowlist re-check + k-suppression + rounding) are applied
// at render in `transparency-view.ts` over the already-materialized stats.
//
// force-dynamic: this page reads live materialized stats and MUST NOT be
// prerendered at build time (that would require a DB during `next build`, and
// would also freeze a stale snapshot into the static output). The read is cheap —
// a handful of indexed materialized rows.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Transparency — Minister",
  description:
    "How Minister's anti-sybil account-strength score works — the full recipe as a price list — plus privacy-guarded badge statistics.",
};

// Per-bucket cost-to-farm price list (design spec §3.7). Static content: the
// defense is cost, not secrecy, so we publish the price of forging each level.
const PRICE_LIST: ReadonlyArray<{ bucket: number; cost: string; meaning: string }> = [
  {
    bucket: 0,
    cost: "No proof",
    meaning: "No verified badges — a fresh or throwaway account.",
  },
  {
    bucket: 1,
    cost: "Free · minutes",
    meaning:
      "Any single proof, e.g. a verified email. Clears a default gate; a zero-proof scraper does not.",
  },
  {
    bucket: 2,
    cost: "Free but slow",
    meaning:
      "Stacking free accounts over time, or one invite plus a verified email. Reachable without spending, but not instantly.",
  },
  {
    bucket: 3,
    cost: "~$2-5 + hours / identity",
    meaning:
      "A second independent root that costs real effort — a controlled domain, or an aged account.",
  },
  {
    bucket: 4,
    cost: "~$50-150 / identity, or multi-year pre-provisioning",
    meaning: "Aged or scarce assets across 3+ independent categories. Not farmable at scale.",
  },
];

// The score-requirement column for each bucket, expressed from the live cutoffs.
function bucketRequirement(
  bucket: number,
  cfg: {
    bucket1Raw: number;
    bucket2Raw: number;
    bucket3Raw: number;
    bucket4Raw: number;
    bucket3MinCats: number;
    bucket4MinCats: number;
  } | null,
): string {
  if (!cfg) return "—";
  switch (bucket) {
    case 0:
      return `raw score < ${cfg.bucket1Raw}`;
    case 1:
      return `raw score ≥ ${cfg.bucket1Raw}`;
    case 2:
      return `raw score ≥ ${cfg.bucket2Raw}`;
    case 3:
      return `raw score ≥ ${cfg.bucket3Raw} across ≥ ${cfg.bucket3MinCats} categories`;
    case 4:
      return `raw score ≥ ${cfg.bucket4Raw} across ≥ ${cfg.bucket4MinCats} categories`;
    default:
      return "—";
  }
}

function AsOfLine({ computedAt }: { computedAt: Date | null }) {
  if (!computedAt) {
    return (
      <p className="text-sm text-neutral-600 dark:text-neutral-400">
        Statistics have not yet been computed.
      </p>
    );
  }
  return (
    <p className="text-xs text-neutral-500">
      As of {computedAt.toLocaleString()}. Counts are rounded and small groups are hidden; no
      history is published.
    </p>
  );
}

export default async function TransparencyPage() {
  const [weightRows, categoryRows, bucketConfig, statsRun, badgeStats, cohortDefs] =
    await Promise.all([
      prisma.badgeWeight.findMany({
        orderBy: [{ category: "asc" }, { badgeType: "asc" }, { qualifier: "asc" }],
        select: { badgeType: true, qualifier: true, sybilWeight: true, category: true },
      }),
      prisma.sybilCategory.findMany({ orderBy: { name: "asc" } }),
      prisma.sybilBucketConfig.findUnique({ where: { id: "singleton" } }),
      prisma.statsRun.findUnique({ where: { id: "singleton" } }),
      prisma.badgeStat.findMany(),
      prisma.cohortStatDef.findMany({ orderBy: { createdAt: "asc" }, include: { stat: true } }),
    ]);

  // Category -> its distinct types (for the caps table).
  const typesByCategory = new Map<string, Set<string>>();
  for (const row of weightRows) {
    const set = typesByCategory.get(row.category) ?? new Set<string>();
    set.add(row.badgeType);
    typesByCategory.set(row.category, set);
  }

  // The three privacy layers are applied HERE, at render, in transparency-view.ts.
  const typeRows = buildPublicTypeRows(badgeStats);
  const cohortRows = cohortDefs.map((def) =>
    buildPublicCohortRow(def.label, def.stat?.numerator ?? 0, def.stat?.denominator ?? 0),
  );

  return (
    <div className="mx-auto flex max-w-4xl flex-col gap-8 px-4 py-12">
      <header className="space-y-3">
        <h1 className="text-3xl font-semibold tracking-tight">Transparency</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Minister gives each account a coarse <strong>account-strength score</strong> (0 to 4) that
          a relying party can gate on without learning which badges you hold. The whole recipe is
          public on purpose: the defense is <strong>cost, not secrecy</strong>.
        </p>
      </header>

      {/* NOT-proof-of-personhood framing — prominent, plainly worded (design spec §2, §1). */}
      <div className="rounded-md border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900 dark:border-amber-900/50 dark:bg-amber-950/30 dark:text-amber-200">
        <p className="font-medium">This score measures cost, not personhood.</p>
        <p className="mt-1">
          The account-strength score answers one question:{" "}
          <em>how expensive would it be to farm this identity as a fake human?</em> It is{" "}
          <strong>not</strong> a claim of unique personhood — it never asserts &ldquo;one distinct
          human.&rdquo; We publish the full recipe as a price list because the wall is the cost of
          forging an account, and that cost is unchanged by anyone knowing how the score is built.
        </p>
      </div>

      {/* ---- Section 1: the score model ---- */}
      <section className="flex flex-col gap-6">
        <h2 className="text-2xl font-semibold tracking-tight">The score model</h2>

        <Card>
          <CardHeader>
            <CardTitle>Price list — what each level costs to fake</CardTitle>
            <CardDescription>
              Rough cost, per identity, to farm an account up to each strength level. Estimates, not
              guarantees; the goal is to make bulk sybils uneconomic, not impossible.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-neutral-200 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800">
                  <th className="py-2 pr-3">Level</th>
                  <th className="py-2 pr-3">Cost to reach</th>
                  <th className="py-2 pr-3">What it means</th>
                  <th className="py-2">Score</th>
                </tr>
              </thead>
              <tbody>
                {PRICE_LIST.map((row) => (
                  <tr
                    key={row.bucket}
                    className="border-b border-neutral-100 align-top last:border-b-0 dark:border-neutral-900"
                  >
                    <td className="py-2 pr-3 font-medium tabular-nums">{row.bucket}</td>
                    <td className="py-2 pr-3 font-medium">{row.cost}</td>
                    <td className="py-2 pr-3 text-neutral-600 dark:text-neutral-400">
                      {row.meaning}
                    </td>
                    <td className="py-2 text-xs text-neutral-500">
                      {bucketRequirement(row.bucket, bucketConfig)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Categories and caps</CardTitle>
            <CardDescription>
              Badges are grouped into categories. Within a category, stacking more badges of the
              same kind yields sharply diminishing returns, and each category&apos;s contribution is
              capped — so bulk-farming one cheap category cannot buy a high score.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-neutral-200 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800">
                  <th className="py-2 pr-3">Category</th>
                  <th className="py-2 pr-3">Cap</th>
                  <th className="py-2">Badge types</th>
                </tr>
              </thead>
              <tbody>
                {categoryRows.map((cat) => (
                  <tr
                    key={cat.name}
                    className="border-b border-neutral-100 align-top last:border-b-0 dark:border-neutral-900"
                  >
                    <td className="py-2 pr-3 font-mono text-xs">{cat.name}</td>
                    <td className="py-2 pr-3 tabular-nums">{cat.cap}</td>
                    <td className="py-2 text-xs text-neutral-600 dark:text-neutral-400">
                      {Array.from(typesByCategory.get(cat.name) ?? [])
                        .sort()
                        .join(", ") || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Per-badge weights</CardTitle>
            <CardDescription>
              The raw cost-to-farm weight of every badge and qualifier, published deliberately. A
              qualifier like <code className="font-mono text-xs">github:24</code> means &ldquo;a
              GitHub account at least 24 months old&rdquo;;{" "}
              <code className="font-mono text-xs">*</code> is the fallback when no more specific
              qualifier matches.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-neutral-200 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800">
                  <th className="py-2 pr-3">Type</th>
                  <th className="py-2 pr-3">Qualifier</th>
                  <th className="py-2 pr-3">Category</th>
                  <th className="py-2 text-right">Weight</th>
                </tr>
              </thead>
              <tbody>
                {weightRows.map((row) => {
                  const meta = getBadgeType(row.badgeType);
                  return (
                    <tr
                      key={`${row.badgeType}:${row.qualifier}`}
                      className="border-b border-neutral-100 last:border-b-0 dark:border-neutral-900"
                    >
                      <td className="py-1.5 pr-3">
                        <code className="font-mono text-xs">{row.badgeType}</code>
                        {meta ? (
                          <span className="ml-2 text-xs text-neutral-500">{meta.label}</span>
                        ) : null}
                      </td>
                      <td className="py-1.5 pr-3 font-mono text-xs">{row.qualifier}</td>
                      <td className="py-1.5 pr-3 font-mono text-xs text-neutral-500">
                        {row.category}
                      </td>
                      <td className="py-1.5 text-right tabular-nums">{row.sybilWeight}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </CardContent>
        </Card>
      </section>

      {/* ---- Section 2: badge statistics (privacy-guarded) ---- */}
      <section className="flex flex-col gap-6">
        <h2 className="text-2xl font-semibold tracking-tight">Badge statistics</h2>

        <Card>
          <CardHeader>
            <CardTitle>Per-type holder counts</CardTitle>
            <CardDescription>
              How many accounts hold each badge type, and the distribution across a small set of
              closed-enum attributes. Counts are rounded and any group smaller than five is shown as{" "}
              <code className="font-mono text-xs">&lt;5</code>. Rare or identifying attribute values
              are never published.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <AsOfLine computedAt={statsRun?.computedAt ?? null} />
            {statsRun === null ? null : typeRows.length === 0 ? (
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                No badges issued yet.
              </p>
            ) : (
              <div className="flex flex-col gap-1.5">
                {typeRows.map((row) => {
                  const meta = getBadgeType(row.type);
                  const hasAttrs = row.attributes.length > 0;
                  const heading = (
                    <span className="flex min-w-0 items-center gap-2">
                      <code className="truncate font-mono text-xs">{row.type}</code>
                      {meta ? (
                        <span className="truncate text-xs text-neutral-500">{meta.label}</span>
                      ) : null}
                    </span>
                  );
                  const total = (
                    <span className="shrink-0 font-medium tabular-nums">{row.totalDisplay}</span>
                  );
                  if (!hasAttrs) {
                    return (
                      <div
                        key={row.type}
                        className="flex items-center justify-between gap-3 rounded-md border border-neutral-200 px-3 py-2 text-sm dark:border-neutral-800"
                      >
                        {heading}
                        {total}
                      </div>
                    );
                  }
                  return (
                    <details
                      key={row.type}
                      className="group rounded-md border border-neutral-200 dark:border-neutral-800"
                    >
                      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-3 py-2 text-sm marker:content-none">
                        <span className="flex min-w-0 items-center gap-2">
                          <span className="inline-block w-[1ch] shrink-0 text-neutral-400 transition-transform group-open:rotate-90">
                            ▸
                          </span>
                          {heading}
                        </span>
                        {total}
                      </summary>
                      <div className="flex flex-col gap-3 border-t border-neutral-200 px-3 py-3 dark:border-neutral-800">
                        {row.attributes.map((group) => (
                          <div key={group.key}>
                            <div className="mb-1 text-xs font-medium uppercase tracking-wide text-neutral-500">
                              {group.key}
                            </div>
                            <table className="w-full text-sm">
                              <tbody>
                                {group.values.map((v) => (
                                  <tr
                                    key={v.value}
                                    className="border-t border-neutral-100 first:border-t-0 dark:border-neutral-900"
                                  >
                                    <td className="py-1 pr-3 font-mono text-xs">{v.value}</td>
                                    <td className="py-1 text-right tabular-nums">{v.display}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        ))}
                      </div>
                    </details>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Cohorts</CardTitle>
            <CardDescription>
              Reviewed proportions, e.g. &ldquo;aged GitHub accounts as a share of GitHub
              accounts&rdquo;. Percentages are derived from the rounded counts, and a cohort too
              small to report is left blank rather than shown precisely.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {cohortRows.length === 0 ? (
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                No cohorts published yet.
              </p>
            ) : (
              <ul className="flex flex-col gap-2">
                {cohortRows.map((row) => (
                  <li
                    key={row.label}
                    className="flex flex-wrap items-baseline justify-between gap-2 rounded-md border border-neutral-200 p-3 dark:border-neutral-800"
                  >
                    <span className="text-sm font-medium">{row.label}</span>
                    <span className="text-sm tabular-nums">
                      {row.numeratorDisplay} of {row.denominatorDisplay}
                      {row.percentDisplay ? (
                        <>
                          {" — "}
                          <span className="font-medium">{row.percentDisplay}</span>
                        </>
                      ) : null}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
