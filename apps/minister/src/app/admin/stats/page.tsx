import { getBadgeType } from "@minister/shared";

import { AdminCohortDefForm } from "@/components/admin-cohort-def-form";
import { AdminCohortPublishToggle } from "@/components/admin-cohort-publish-toggle";
import { AdminStatsRecomputeButton } from "@/components/admin-stats-recompute-button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { CohortStat, CohortStatDef, StatsRun } from "@/generated/prisma";
import { prisma } from "@/lib/prisma";
import { requireAdmin } from "@/lib/session";

// /admin/stats (phase-2 impl brief §5). Reads ONLY the materialized tables
// (BadgeStat/CohortStat/StatsRun) — never a live COUNT(DISTINCT ...) — so this
// page is cheap regardless of instance size. Exact counts throughout: this is
// operator-only, unlike the (not-yet-built) k-suppressed public transparency
// page.

interface AttrRow {
  value: string;
  count: number;
}

interface TypeRow {
  type: string;
  count: number;
  pct: number;
  attributesByKey: Map<string, AttrRow[]>;
}

// Groups the flat BadgeStat rows (one row per type-level total, one row per
// (type, attributeKey, attributeValue)) into a per-type view: the type-level
// total plus its attribute distributions grouped by key, each sorted by count
// descending so the biggest slice reads first.
function buildTypeRows(
  badgeStats: Array<{
    badgeType: string;
    attributeKey: string;
    attributeValue: string;
    count: number;
  }>,
  totalUsers: number,
): TypeRow[] {
  const byType = new Map<string, TypeRow>();
  function rowFor(type: string): TypeRow {
    let row = byType.get(type);
    if (!row) {
      row = { type, count: 0, pct: 0, attributesByKey: new Map() };
      byType.set(type, row);
    }
    return row;
  }

  for (const stat of badgeStats) {
    const row = rowFor(stat.badgeType);
    if (stat.attributeKey === "" && stat.attributeValue === "") {
      row.count = stat.count;
      continue;
    }
    const values = row.attributesByKey.get(stat.attributeKey) ?? [];
    values.push({ value: stat.attributeValue, count: stat.count });
    row.attributesByKey.set(stat.attributeKey, values);
  }

  for (const row of byType.values()) {
    row.pct = totalUsers > 0 ? (row.count / totalUsers) * 100 : 0;
    for (const values of row.attributesByKey.values()) {
      values.sort((a, b) => b.count - a.count);
    }
  }

  return Array.from(byType.values()).sort((a, b) => b.count - a.count);
}

// A relative + absolute rendering of `computedAt`, e.g. "12 minutes ago (Jul 11,
// 2026, 3:45 PM)". Both ends of the freshness signal so an admin doesn't have to
// do clock math to tell whether a run is fresh.
function relativeTime(date: Date, now: Date): string {
  const diffSec = Math.round((now.getTime() - date.getTime()) / 1000);
  const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  const divisions: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ["year", 60 * 60 * 24 * 365],
    ["month", 60 * 60 * 24 * 30],
    ["week", 60 * 60 * 24 * 7],
    ["day", 60 * 60 * 24],
    ["hour", 60 * 60],
    ["minute", 60],
  ];
  for (const [unit, secs] of divisions) {
    if (Math.abs(diffSec) >= secs) return rtf.format(Math.round(-diffSec / secs), unit);
  }
  return rtf.format(-diffSec, "second");
}

function FreshnessLine({ statsRun }: { statsRun: StatsRun | null }) {
  if (!statsRun) {
    return (
      <div className="flex flex-wrap items-center gap-3">
        <AdminStatsRecomputeButton />
        <span className="text-xs text-neutral-500">Never computed.</span>
      </div>
    );
  }
  const now = new Date();
  return (
    <div className="flex flex-wrap items-center gap-3">
      <AdminStatsRecomputeButton />
      <span className="text-xs text-neutral-500">
        As of {relativeTime(statsRun.computedAt, now)} ({statsRun.computedAt.toLocaleString()}) ·{" "}
        {statsRun.durationMs}ms
      </span>
    </div>
  );
}

function TypeDisclosure({ row }: { row: TypeRow }) {
  const meta = getBadgeType(row.type);
  const hasAttrs = row.attributesByKey.size > 0;

  const body = (
    <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-3 py-2 text-sm marker:content-none">
      <span className="flex min-w-0 items-center gap-2">
        <span
          className={
            hasAttrs
              ? "inline-block w-[1ch] shrink-0 text-neutral-400 transition-transform group-open:rotate-90"
              : "inline-block w-[1ch] shrink-0"
          }
        >
          {hasAttrs ? "▸" : ""}
        </span>
        <code className="truncate font-mono text-xs">{row.type}</code>
        {meta ? <span className="truncate text-xs text-neutral-500">{meta.label}</span> : null}
      </span>
      <span className="flex shrink-0 items-baseline gap-3 tabular-nums">
        <span className="font-medium">{row.count.toLocaleString()}</span>
        <span className="w-16 text-right text-xs text-neutral-500">{row.pct.toFixed(1)}%</span>
      </span>
    </summary>
  );

  if (!hasAttrs) {
    return (
      <div className="rounded-md border border-neutral-200 dark:border-neutral-800">
        <div className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
          <span className="flex min-w-0 items-center gap-2">
            <span className="inline-block w-[1ch] shrink-0" />
            <code className="truncate font-mono text-xs">{row.type}</code>
            {meta ? <span className="truncate text-xs text-neutral-500">{meta.label}</span> : null}
          </span>
          <span className="flex shrink-0 items-baseline gap-3 tabular-nums">
            <span className="font-medium">{row.count.toLocaleString()}</span>
            <span className="w-16 text-right text-xs text-neutral-500">{row.pct.toFixed(1)}%</span>
          </span>
        </div>
      </div>
    );
  }

  return (
    <details className="group rounded-md border border-neutral-200 dark:border-neutral-800">
      {body}
      <div className="flex flex-col gap-3 border-t border-neutral-200 px-3 py-3 dark:border-neutral-800">
        {Array.from(row.attributesByKey.entries()).map(([key, values]) => (
          <div key={key}>
            <div className="mb-1 text-xs font-medium uppercase tracking-wide text-neutral-500">
              {key}
            </div>
            <table className="w-full text-sm">
              <tbody>
                {values.map((v) => (
                  <tr
                    key={v.value}
                    className="border-t border-neutral-100 first:border-t-0 dark:border-neutral-900"
                  >
                    <td className="py-1 pr-3 font-mono text-xs">{v.value}</td>
                    <td className="py-1 text-right tabular-nums">{v.count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      </div>
    </details>
  );
}

function CohortRow({ def }: { def: CohortStatDef & { stat: CohortStat | null } }) {
  const stat = def.stat;
  return (
    <li className="flex flex-col gap-2 rounded-md border border-neutral-200 p-3 dark:border-neutral-800">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm font-medium">{def.label}</span>
        <AdminCohortPublishToggle id={def.id} published={def.published} />
      </div>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="text-xs text-neutral-500">
          {def.published ? "Visible on /transparency" : "Not shown publicly"}
        </span>
        {stat ? (
          <span className="tabular-nums text-sm">
            {stat.numerator.toLocaleString()} of {stat.denominator.toLocaleString()} —{" "}
            <span className="font-medium">
              {stat.denominator > 0
                ? ((stat.numerator / stat.denominator) * 100).toFixed(1)
                : "0.0"}
              %
            </span>
          </span>
        ) : (
          <span className="text-xs text-neutral-500">pending next recompute</span>
        )}
      </div>
    </li>
  );
}

export default async function AdminStatsPage() {
  await requireAdmin();

  const [statsRun, badgeStats, cohortDefs, totalUsers] = await Promise.all([
    prisma.statsRun.findUnique({ where: { id: "singleton" } }),
    prisma.badgeStat.findMany(),
    prisma.cohortStatDef.findMany({ orderBy: { createdAt: "asc" }, include: { stat: true } }),
    prisma.user.count(),
  ]);

  const typeRows = buildTypeRows(badgeStats, totalUsers);

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Badge statistics</CardTitle>
          <CardDescription>
            Exact, operator-only counts read from the materialized stats tables — for tuning the
            anti-sybil weights against the real badge distribution. The (not-yet-built) public
            transparency page applies k-suppression and rounding on top of this same data; this view
            doesn&apos;t.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FreshnessLine statsRun={statsRun} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Per-type holder counts</CardTitle>
          <CardDescription>
            Distinct native, unexpired holders out of {totalUsers.toLocaleString()} total user
            {totalUsers === 1 ? "" : "s"}. Expand a type for its allowlisted attribute distribution.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {statsRun === null ? (
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              Not yet computed — click <span className="font-medium">Recompute now</span> above.
            </p>
          ) : typeRows.length === 0 ? (
            <p className="text-sm text-neutral-600 dark:text-neutral-400">No badges issued yet.</p>
          ) : (
            <div className="flex flex-col gap-1.5">
              {typeRows.map((row) => (
                <TypeDisclosure key={row.type} row={row} />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Cohorts</CardTitle>
          <CardDescription>
            Operator-defined numerator/denominator badge filters, e.g. &ldquo;aged GitHub accounts
            as a share of GitHub accounts&rdquo;. A new definition counts as of the next recompute.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {cohortDefs.length === 0 ? (
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              No cohort definitions yet.
            </p>
          ) : (
            <ul className="flex flex-col gap-2">
              {cohortDefs.map((def) => (
                <CohortRow key={def.id} def={def} />
              ))}
            </ul>
          )}
          <div className="border-t border-neutral-200 pt-4 dark:border-neutral-800">
            <h3 className="mb-2 text-sm font-semibold">Add a cohort</h3>
            <AdminCohortDefForm />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
