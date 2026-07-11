// Cohort filter format + distinct-user counting (design spec §10, phase-2 impl
// brief §3). A cohort side is a Zod-validated conjunction of 1-3 badge filters;
// its distinct-holder count is computed via EXISTS subqueries over unexpired
// native badges.
//
// SQL-INJECTION SAFETY (mandatory, brief §3):
//   * Every VALUE (badge type, attribute value, timestamp, native issuer DID) is
//     bound as a Prisma parameter via `Prisma.sql`. Nothing user-supplied is ever
//     string-interpolated into the query text.
//   * KEYS are never taken raw from input. Validation rejects any key not on the
//     stats allowlist (stats-allowlist.ts) BEFORE any SQL is built, so a def can
//     only ever reference a closed set of code-owned literals. Belt-and-suspenders,
//     the key is ALSO bound as a parameter to the `->>` operator (jsonb ->> text),
//     never spliced into the SQL text.
//   * The only non-parameter tokens are the table name and the correlation
//     aliases (`b1`, `b2`, `b3`) — fixed, code-owned constants, never input.
//
// The design is proven by cohort-filter.test.ts: a malicious key or value is
// rejected at validation and can never reach the SQL builder.

import { z } from "zod";

import { getBadgeType } from "@minister/shared";

import { Prisma } from "@/generated/prisma";
import { prisma } from "@/lib/prisma";
import { isAllowlistedKey } from "@/lib/stats-allowlist";

// ---------------------------------------------------------------------------
// Zod schema
// ---------------------------------------------------------------------------

const MAX_CLAUSES = 3;

const clauseSchema = z
  .object({
    type: z.string().min(1),
    where: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
    whereGte: z.record(z.string(), z.number()).optional(),
  })
  .strict()
  .superRefine((clause, ctx) => {
    if (!getBadgeType(clause.type)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["type"],
        message: `Unknown badge type "${clause.type}"`,
      });
      // Without a known type we cannot allowlist-check its keys; stop here.
      return;
    }
    for (const [group, obj] of [
      ["where", clause.where],
      ["whereGte", clause.whereGte],
    ] as const) {
      if (!obj) continue;
      for (const key of Object.keys(obj)) {
        if (!isAllowlistedKey(clause.type, key)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [group, key],
            message: `Key "${key}" is not an allowlisted attribute for type "${clause.type}"`,
          });
        }
      }
    }
  });

export const cohortFilterSchema = z.object({
  clauses: z.array(clauseSchema).min(1).max(MAX_CLAUSES),
});

export type CohortClause = z.infer<typeof clauseSchema>;
export type CohortFilter = z.infer<typeof cohortFilterSchema>;

/**
 * Parse + validate an untrusted CohortFilter (a stored Json def or an admin form
 * submission). Throws a ZodError on any unknown type or non-allowlisted key —
 * fail-closed, so a malformed def never reaches the SQL builder.
 */
export function parseCohortFilter(input: unknown): CohortFilter {
  return cohortFilterSchema.parse(input);
}

/** Non-throwing variant for the recompute (skip-and-log a malformed stored def). */
export function safeParseCohortFilter(input: unknown): CohortFilter | null {
  const result = cohortFilterSchema.safeParse(input);
  return result.success ? result.data : null;
}

// ---------------------------------------------------------------------------
// Built-in seeded cohort (design spec §5.5, brief §3): "aged github accounts as
// a fraction of github accounts". denominator = oauth-account{provider=github};
// numerator = account-age{provider=github, olderThanMonths>=24}. Seeded
// idempotently by seed-sybil-config.ts.
// ---------------------------------------------------------------------------

export interface CohortDefSeed {
  label: string;
  numeratorFilter: CohortFilter;
  denominatorFilter: CohortFilter;
}

export const BUILTIN_COHORT_DEFS: readonly CohortDefSeed[] = [
  {
    label: "Aged GitHub accounts (share of GitHub accounts)",
    denominatorFilter: {
      clauses: [{ type: "oauth-account", where: { provider: "github" } }],
    },
    numeratorFilter: {
      clauses: [
        { type: "account-age", where: { provider: "github" }, whereGte: { olderThanMonths: 24 } },
      ],
    },
  },
];

// ---------------------------------------------------------------------------
// Injection-safe SQL builder
// ---------------------------------------------------------------------------

// A DB handle that can run a raw query — the global client OR a transaction
// client. Both expose `$queryRaw` accepting a `Prisma.Sql`.
type RawClient = Pick<typeof prisma, "$queryRaw">;

interface CountRow {
  // COUNT(...) comes back as Postgres bigint -> JS bigint through $queryRaw.
  count: bigint;
}

// The native-issuer + unexpired predicate for a given alias. `native` and `now`
// are bound parameters; the alias is a code-owned constant.
function nativeUnexpired(alias: string, native: string, now: Date): Prisma.Sql {
  const a = Prisma.raw(alias);
  return Prisma.sql`${a}."issuer" = ${native} AND (${a}."expiresAt" IS NULL OR ${a}."expiresAt" > ${now})`;
}

// The predicates for one clause on a given alias: the type match plus each
// where/whereGte comparison. Every key and value is a bound parameter.
function clausePredicates(alias: string, clause: CohortClause): Prisma.Sql {
  const a = Prisma.raw(alias);
  const parts: Prisma.Sql[] = [Prisma.sql`${a}."type" = ${clause.type}`];

  for (const [key, value] of Object.entries(clause.where ?? {})) {
    // jsonb ->> text (key bound as a param) compared to the value as text. The
    // stored attribute is JSON; `->>` yields its text form, so coerce the
    // comparand to text too (a JSON number/bool stringifies to "24"/"true").
    parts.push(Prisma.sql`${a}."attributes"->>${key} = ${String(value)}`);
  }
  for (const [key, value] of Object.entries(clause.whereGte ?? {})) {
    // Numeric tiers (olderThanMonths/followersAtLeast/threshold) are stored as
    // the highest satisfied tier, so a `>=` sums the tiers. The key is a bound
    // param; the stored text is cast to int for the comparison.
    parts.push(Prisma.sql`(${a}."attributes"->>${key})::int >= ${value}`);
  }
  return Prisma.join(parts, " AND ");
}

/**
 * Build the injection-safe distinct-user COUNT for a cohort side. The anchor
 * clause drives `FROM "Badge" b1`; each further clause is an `EXISTS` subquery
 * correlated on `userId`. All clauses are ANDed (a conjunction). Every value and
 * key is bound; only the table name and the fixed aliases are literal.
 *
 * `filter.clauses.length` is 1..3 (Zod-enforced), so at most `b1`/`b2`/`b3`.
 */
export function buildCohortCountSql(filter: CohortFilter, native: string, now: Date): Prisma.Sql {
  const clauses = filter.clauses;
  const anchor = clauses[0];
  // Guarded by the schema's `.min(1)`, but keep TS honest.
  if (!anchor) throw new Error("cohort filter has no clauses");

  // The anchor drives `FROM "Badge" b1`; each further clause is an EXISTS
  // subquery on `b2`/`b3`. Aliases are computed constants (schema caps clauses at
  // 3), NEVER derived from input, so they are safe to emit as raw identifiers.
  const conds: Prisma.Sql[] = [clausePredicates("b1", anchor), nativeUnexpired("b1", native, now)];

  for (let i = 1; i < clauses.length; i++) {
    const clause = clauses[i]!;
    const alias = `b${i + 1}`;
    const a = Prisma.raw(alias);
    conds.push(
      Prisma.sql`EXISTS (SELECT 1 FROM "Badge" ${a} WHERE ${a}."userId" = b1."userId" AND ${clausePredicates(
        alias,
        clause,
      )} AND ${nativeUnexpired(alias, native, now)})`,
    );
  }

  return Prisma.sql`SELECT COUNT(DISTINCT b1."userId")::bigint AS count FROM "Badge" b1 WHERE ${Prisma.join(
    conds,
    " AND ",
  )}`;
}

/**
 * Count the distinct native, unexpired holders satisfying a cohort side.
 *
 * @param filter a validated CohortFilter (call `parseCohortFilter` first for
 *               untrusted input — this trusts its clauses are allowlist-clean).
 * @param native Minister's own issuer DID (only native badges count).
 * @param now    the expiry clock.
 * @param client optional DB handle (a transaction client); defaults to global.
 */
export async function countCohortSide(
  filter: CohortFilter,
  native: string,
  now: Date,
  client: RawClient = prisma,
): Promise<number> {
  const rows = await client.$queryRaw<CountRow[]>(buildCohortCountSql(filter, native, now));
  return rows.length > 0 ? Number(rows[0]!.count) : 0;
}
