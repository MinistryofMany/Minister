# Lines Slice 1 — Relay Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Double-blind email alias relay on the hosted domain — manual alias mint in the wallet, both relay directions with allowlist rewrite, reverse-alias sender verification, loop guard, drop-on-revoked, bounce/complaint auto-pause.

**Architecture:** SES receives all mail for the hosted domain (catch-all receipt rule → S3 → SQS). A new `services/relay-worker` Node service long-polls SQS, runs pure decision/rewrite logic from a new `packages/relay-core` workspace package, re-sends via SESv2, and records metadata-only logs via Prisma (same schema as the app). The wallet gets a `/lines` page + server actions for mint/pause/cut. Spec: `docs/contact-channels-design.md` (READ IT FIRST — the "Double-blind protocol", "Abuse controls", and "Line-state semantics" sections are the requirements).

**Tech Stack:** TypeScript strict, pnpm workspace, Prisma 6/Postgres, `@aws-sdk/client-{s3,sqs,sesv2}`, `mailparser`, Zod, Vitest.

## Global Constraints

- TypeScript strict; no `any`; no `@ts-ignore` without inline justification. Zod at every boundary (env, action inputs).
- Conventional commits under the repo's configured git identity; NO tool/assistant attribution anywhere.
- **Domain floor:** Tasks 4–7 are security/protocol code — implementer must be engineer-tier (Opus) or higher; after Tasks 4–7 land, an auditor (Fable) adversarial review is REQUIRED before the slice ships (checklists in spec "Verification" section).
- **Never log message bodies, subjects, or real addresses** in worker output or audit metadata — ids, localparts of OUR domain, and drop reasons only.
- **Storage-free relay:** delete the S3 object after terminal handling; `LineMessageLog` stores metadata only, NO Subject column, ever.
- Header handling is ALLOWLIST-only (spec "Double-blind protocol"). Body bytes pass untouched — no body rewriting.
- Slice-1 interim threading policy: inbound (external→user) keeps `In-Reply-To`/`References` verbatim; outbound (user→external) DROPS them (avoids leaking the user's mail-provider domain via Message-IDs). AES-SIV translation is slice 2.
- Hosted domain comes from env `RELAY_HOSTED_DOMAIN` (e.g. `relay.example`). NO ContactDomain model in this slice (BYO is slice 3).
- Commands run from repo root (`Minister/`). Node 20+, pnpm.

---

### Task 1: AWS runbook + SES production-access request (ops, day 1 — zero code, longest lead time)

**Files:**

- Create: `services/relay-worker/AWS-SETUP.md`

**Interfaces:**

- Produces: queue URLs / bucket name / config-set name consumed as env by Task 6; the **spike verdict** (are `X-SES-Spam-Verdict` / `Authentication-Results` headers present on the S3 object?) consumed by Task 6 Step 3.

- [ ] **Step 1: Write the runbook** with these sections, exact commands, all in `us-east-2` (account already hosts KMS/SSM there):
  1. **S3**: `aws s3api create-bucket --bucket minister-relay-inbound --region us-east-2 --create-bucket-configuration LocationConstraint=us-east-2`; default SSE (S3-managed keys is fine for v1 — SSE-KMS requires an SES grant, note as follow-up); lifecycle rule expiring objects after 7 days (`put-bucket-lifecycle-configuration`, `{"Rules":[{"ID":"relay-backstop","Status":"Enabled","Filter":{},"Expiration":{"Days":7}}]}`); bucket policy allowing `ses.amazonaws.com` to `s3:PutObject` with `aws:SourceAccount` condition.
  2. **SQS**: `relay-inbound-dlq`, then `relay-inbound` with `RedrivePolicy` maxReceiveCount 5, `VisibilityTimeout` 300, `MessageRetentionPeriod` 1209600 (14d); same pair for `relay-events`; queue policy allowing `s3.amazonaws.com` SendMessage from the bucket ARN.
  3. **S3 → SQS event notification**: `put-bucket-notification-configuration` for `s3:ObjectCreated:*` → `relay-inbound` queue ARN.
  4. **SES identity**: `aws sesv2 create-email-identity --email-identity <hosted-domain>`; publish the 3 DKIM CNAMEs + `MX 10 inbound-smtp.us-east-2.amazonaws.com` at the domain's DNS (Cloudflare, DNS-only); poll `aws sesv2 get-email-identity` until `DkimAttributes.Status=SUCCESS`.
  5. **Receipt rule**: `aws ses create-receipt-rule-set --rule-set-name minister-relay`; one rule, NO recipient condition (catch-all), `ScanEnabled=true`, S3 action into the bucket; `set-active-receipt-rule-set`. **WARNING in bold: the active rule set is an account/region singleton — check `describe-active-receipt-rule-set` first and never clobber an existing one.**
  6. **Config set + events**: `aws sesv2 create-configuration-set --configuration-set-name minister-relay`; event destination for `BOUNCE,COMPLAINT` → SNS topic `relay-events-topic` → subscribed to `relay-events` queue (raw delivery).
  7. **Production access request** (file NOW; sandbox blocks sending to arbitrary addresses): template text describing the product (identity-attached, consent-based alias forwarding; per-user quotas; bounce/complaint auto-pause; complaint target <0.1%; no bulk/marketing mail), expected volume, and the abuse-controls section of the spec pasted in.
  8. **Spike procedure**: send a test mail to `anything@<hosted-domain>`, `aws s3 cp` the object, inspect: are `X-SES-Spam-Verdict`, `X-SES-Virus-Verdict`, `Authentication-Results` (with spf/dkim/dmarc results) present as headers? Record the answer in a "## Spike results" section of this file. If verdicts are MISSING, the fallback is receipt-rule S3 action + SNS notification → relay-inbound (message then contains the `receipt` object) — note which path was taken.
- [ ] **Step 2: Execute sections 1–8** against the real account (needs an `aws` session; static creds for the worker come later). Record outputs (queue URLs, bucket, spike result) in the runbook.
- [ ] **Step 3: Commit**

```bash
git add services/relay-worker/AWS-SETUP.md
git commit -m "docs(relay): AWS SES/S3/SQS setup runbook + production access request"
```

---

### Task 2: Prisma models + middleware gate

**Files:**

- Modify: `apps/minister/prisma/schema.prisma` (append after `NullifierRpCheck`; add back-relations on `User` and `UserEmail`)
- Modify: `apps/minister/src/middleware.ts` (matcher array)

**Interfaces:**

- Produces: models `Line`, `ReverseAlias`, `LineMessageLog` exactly as below — Tasks 5–9 depend on these field names.

- [ ] **Step 1: Append models to schema.prisma**

```prisma
// ---------------------------------------------------------------------------
// Lines — relay slice 1 (docs/contact-channels-design.md)
// ---------------------------------------------------------------------------

// A revocable relationship-scoped email alias on the hosted relay domain.
// displayName is REQUIRED and never falls back to User.name/displayName
// (same discipline as oidc-claims).
model Line {
  id              String    @id @default(cuid())
  ownerId         String
  alias           String    @unique // full lowercase address, e.g. "tyler.x7k2q@relay.example"
  label           String
  displayName     String
  source          String    @default("manual") // request | share-link arrive in later slices
  status          String    @default("active") // active | paused | revoked
  deliveryEmailId String
  inboundCount    Int       @default(0)
  droppedCount    Int       @default(0)
  lastInboundAt   DateTime?
  createdAt       DateTime  @default(now())
  revokedAt       DateTime?

  owner          User             @relation(fields: [ownerId], references: [id], onDelete: Cascade)
  deliveryEmail  UserEmail        @relation(fields: [deliveryEmailId], references: [id], onDelete: Restrict)
  reverseAliases ReverseAlias[]
  messages       LineMessageLog[]

  @@index([ownerId, status])
}

// One external correspondent on one line. Outbound destination is looked up
// FROM THIS ROW, never from header content (spec: structurally kills open-relay).
model ReverseAlias {
  id              String    @id @default(cuid())
  lineId          String
  localpart       String    @unique // "ra.<token>" — full address is localpart@RELAY_HOSTED_DOMAIN
  externalAddress String // canonicalized (trimmed, lowercased)
  externalName    String?
  createdAt       DateTime  @default(now())
  lastUsedAt      DateTime?

  line Line @relation(fields: [lineId], references: [id], onDelete: Cascade)

  @@unique([lineId, externalAddress])
}

// Metadata-only relay log. NO subject, NO bodies, NO external addresses in
// clear beyond what ReverseAlias already holds. sesMessageId (== S3 key) is
// the idempotency key; sentMessageId correlates bounce/complaint events.
model LineMessageLog {
  id            String    @id @default(cuid())
  lineId        String
  direction     String // inbound | outbound
  sesMessageId  String    @unique
  sentMessageId String?   @unique
  status        String // processing | forwarded | dropped
  dropReason    String?
  sizeBytes     Int
  spamVerdict   String?
  virusVerdict  String?
  receivedAt    DateTime  @default(now())
  processedAt   DateTime?
  latencyMs     Int?

  line Line @relation(fields: [lineId], references: [id], onDelete: Cascade)

  @@index([lineId, receivedAt])
  @@index([direction, receivedAt])
}
```

Add to `model User` relations block: `lines Line[]`. Add to `model UserEmail`: `lines Line[]`.

- [ ] **Step 2: Validate + migrate**

Run: `pnpm --filter @minister/app exec prisma validate` → `The schema ... is valid`
Run: `pnpm --filter @minister/app exec prisma migrate dev --name lines-relay-core` (compose postgres must be up) → migration created + applied.

- [ ] **Step 3: Gate /lines in middleware** — in `apps/minister/src/middleware.ts` `config.matcher`, add `"/lines/:path*"` after `"/shares/:path*"`.

- [ ] **Step 4: Typecheck**

Run: `pnpm --filter @minister/app typecheck` → clean.

- [ ] **Step 5: Commit**

```bash
git add apps/minister/prisma apps/minister/src/middleware.ts
git commit -m "feat(lines): Line/ReverseAlias/LineMessageLog models + /lines route gate"
```

---

### Task 3: `@minister/relay-core` package + address module

**Files:**

- Create: `packages/relay-core/package.json`, `packages/relay-core/tsconfig.json`, `packages/relay-core/src/index.ts`, `packages/relay-core/src/address.ts`
- Test: `packages/relay-core/src/address.test.ts`

**Interfaces:**

- Produces: `mintAliasLocalpart(prefix): string`, `mintReverseAliasLocalpart(): string`, `classifyLocalpart(lp): "alias" | "reverse-alias"`, `canonicalizeAddress(addr): string`, `isValidAliasPrefix(prefix): boolean`, const `RA_PREFIX = "ra."`. Consumed by Tasks 5, 6, 8.

- [ ] **Step 1: Package scaffold** — mirror the source-exposed pattern of `packages/shared`:

`package.json`:

```json
{
  "name": "@minister/relay-core",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "main": "./src/index.ts",
  "types": "./src/index.ts",
  "scripts": {
    "test": "vitest run",
    "typecheck": "tsc --noEmit",
    "lint": "echo relay-core: no lint config, typecheck covers"
  },
  "dependencies": { "mailparser": "^3.7.1" },
  "devDependencies": {
    "@types/mailparser": "^3.4.5",
    "@types/node": "^22.10.2",
    "typescript": "^5.6.3",
    "vitest": "^3.2.6"
  }
}
```

`tsconfig.json`: copy `packages/shared/tsconfig.json` verbatim (strict, noUncheckedIndexedAccess). `src/index.ts`: `export * from "./address.js";` (match the shared package's import-extension convention — check `packages/shared/src/index.ts` and mirror it).

- [ ] **Step 2: Write failing tests** (`src/address.test.ts`):

```ts
import { describe, expect, it } from "vitest";
import {
  RA_PREFIX,
  canonicalizeAddress,
  classifyLocalpart,
  isValidAliasPrefix,
  mintAliasLocalpart,
  mintReverseAliasLocalpart,
} from "./address.js";

describe("address", () => {
  it("mints alias as prefix.token6 from the safe alphabet", () => {
    const lp = mintAliasLocalpart("tyler");
    expect(lp).toMatch(/^tyler\.[a-z2-9]{6}$/);
    expect(lp).not.toMatch(/[01ilou]/);
  });
  it("rejects invalid prefixes", () => {
    for (const bad of ["", "Tyler", "a b", "-x", "ra", "ra.foo", "x".repeat(21)]) {
      expect(isValidAliasPrefix(bad), bad).toBe(false);
      expect(() => mintAliasLocalpart(bad)).toThrow();
    }
    expect(isValidAliasPrefix("tyler-2")).toBe(true);
  });
  it("mints reverse aliases in the ra. namespace", () => {
    expect(mintReverseAliasLocalpart()).toMatch(/^ra\.[a-z2-9]{16}$/);
  });
  it("classifies localparts", () => {
    expect(classifyLocalpart("ra.abcdefgh23456789")).toBe("reverse-alias");
    expect(classifyLocalpart("tyler.x7k2qm")).toBe("alias");
  });
  it("canonicalizes addresses", () => {
    expect(canonicalizeAddress("  Bob.Smith@GMail.com ")).toBe("bob.smith@gmail.com");
  });
});
```

- [ ] **Step 3: Run to verify failure**

Run: `pnpm --filter @minister/relay-core test` → FAIL (module not found).

- [ ] **Step 4: Implement `src/address.ts`**

```ts
import { randomInt } from "node:crypto";

// No 0/1/i/l/o/u — aliases get read aloud and retyped.
const ALPHABET = "abcdefghjkmnpqrstvwxyz23456789";
export const RA_PREFIX = "ra.";
const PREFIX_RE = /^[a-z0-9][a-z0-9-]{0,19}$/;

function token(len: number): string {
  let out = "";
  for (let i = 0; i < len; i++) out += ALPHABET[randomInt(ALPHABET.length)];
  return out;
}

export function isValidAliasPrefix(prefix: string): boolean {
  // "ra" is reserved so alias localparts can never collide with the
  // reverse-alias namespace.
  return PREFIX_RE.test(prefix) && prefix !== "ra" && !prefix.startsWith(RA_PREFIX);
}

export function mintAliasLocalpart(prefix: string): string {
  if (!isValidAliasPrefix(prefix)) throw new Error("invalid alias prefix");
  return `${prefix}.${token(6)}`;
}

export function mintReverseAliasLocalpart(): string {
  return `${RA_PREFIX}${token(16)}`;
}

export function classifyLocalpart(localpart: string): "alias" | "reverse-alias" {
  return localpart.startsWith(RA_PREFIX) ? "reverse-alias" : "alias";
}

export function canonicalizeAddress(addr: string): string {
  return addr.trim().toLowerCase();
}
```

- [ ] **Step 5: Run tests + typecheck** — `pnpm --filter @minister/relay-core test` PASS; `pnpm --filter @minister/relay-core typecheck` clean. Root `pnpm test` still green (new package joins the `-r` run).

- [ ] **Step 6: Commit**

```bash
git add packages/relay-core
git commit -m "feat(relay-core): package scaffold + alias/reverse-alias address module"
```

---

### Task 4: Rewrite engine (header allowlist surgery) — DOMAIN FLOOR

**Files:**

- Create: `packages/relay-core/src/rewrite.ts`
- Test: `packages/relay-core/src/rewrite.test.ts`
- Modify: `packages/relay-core/src/index.ts` (add export)

**Interfaces:**

- Produces (consumed by Task 6):

```ts
export interface Participant {
  externalAddress: string;
  reverseAliasAddress: string;
  displayName?: string;
}
export interface InboundRewriteInput {
  kind: "inbound";
  raw: Buffer;
  relayDomain: string;
  aliasAddress: string; // becomes To
  sender: Participant; // becomes From (via reverse alias)
  others: Participant[]; // remaining To/Cc -> Cc as reverse aliases
  loopStamp: string;
  tagSpam: boolean;
}
export interface OutboundRewriteInput {
  kind: "outbound";
  raw: Buffer;
  relayDomain: string;
  aliasAddress: string;
  lineDisplayName: string;
  toExternal: string[]; // resolved from ReverseAlias rows ONLY
  loopStamp: string;
}
export function rewriteMessage(input: InboundRewriteInput | OutboundRewriteInput): Buffer;
```

**The protocol rules being implemented (spec "Double-blind protocol"):** ALLOWLIST copy from original: `Subject` (with `[SPAM] ` prefix when tagSpam), `Date`, `MIME-Version`, `Content-Type`, `Content-Transfer-Encoding`, `Content-Disposition`, `Auto-Submitted`, and (inbound only) `In-Reply-To` + `References`. REGENERATED: `From`, `To`, `Cc` (inbound, only when `others` non-empty), `Message-ID` (`<r.<24 hex>@relayDomain>`), `X-Minister-Relay: <loopStamp>`. Everything else — Received, DKIM-Signature, ARC-_, Authentication-Results, Reply-To, Disposition-Notification-To, Return-Path, Bcc, X-_ — does not survive. Body bytes are appended VERBATIM (boundary strings in the copied Content-Type stay valid). Never emit Reply-To.

- [ ] **Step 1: Write failing tests.** Build fixtures inline as template strings with `\r\n` endings. Required cases:

```ts
import { describe, expect, it } from "vitest";
import { rewriteMessage } from "./rewrite.js";

const CRLF = "\r\n";
const BODY = [
  "--b1",
  'Content-Type: text/plain; charset="utf-8"',
  "",
  "hi there",
  "--b1",
  "Content-Type: application/pdf; name=x.pdf",
  "Content-Transfer-Encoding: base64",
  "",
  "QUJD",
  "--b1--",
  "",
].join(CRLF);
const RAW = [
  "Received: from mail.example by mx (SES)",
  "DKIM-Signature: v=1; a=rsa-sha256; d=gmail.com; s=x; b=abc",
  'From: "Alice Smith" <alice@gmail.com>',
  "Reply-To: alice-real@gmail.com",
  "To: tyler.x7k2qm@relay.example, carol@corp.com",
  "Subject: Hello",
  "Date: Sat, 12 Jul 2026 10:00:00 -0400",
  "Message-ID: <abc@mail.gmail.com>",
  "In-Reply-To: <prev@mail.gmail.com>",
  "References: <prev@mail.gmail.com>",
  "MIME-Version: 1.0",
  "Content-Type: multipart/mixed;",
  ' boundary="b1"', // folded header — must survive verbatim
  "X-Mailer: Gmail",
  "",
  BODY,
].join(CRLF);

const inbound = {
  kind: "inbound" as const,
  raw: Buffer.from(RAW),
  relayDomain: "relay.example",
  aliasAddress: "tyler.x7k2qm@relay.example",
  sender: {
    externalAddress: "alice@gmail.com",
    reverseAliasAddress: "ra.aaaabbbbccccdddd@relay.example",
    displayName: "Alice Smith",
  },
  others: [
    {
      externalAddress: "carol@corp.com",
      reverseAliasAddress: "ra.eeeeffffgggghhhh@relay.example",
      displayName: undefined,
    },
  ],
  loopStamp: "stamp123",
  tagSpam: false,
};

describe("rewriteMessage inbound", () => {
  const out = rewriteMessage(inbound).toString("utf8");
  const [head, ...rest] = out.split(CRLF + CRLF);
  const headers = head!;
  const body = rest.join(CRLF + CRLF);
  it("body bytes pass through verbatim", () => expect(body).toBe(BODY));
  it("keeps folded Content-Type boundary verbatim", () =>
    expect(headers).toContain("Content-Type: multipart/mixed;" + CRLF + ' boundary="b1"'));
  it("From is the sender reverse alias with via display name", () =>
    expect(headers).toContain(
      'From: "Alice Smith (via relay.example)" <ra.aaaabbbbccccdddd@relay.example>',
    ));
  it("To is the alias; Cc rewritten to reverse aliases", () => {
    expect(headers).toContain("To: tyler.x7k2qm@relay.example");
    expect(headers).toContain("Cc: ra.eeeeffffgggghhhh@relay.example");
  });
  it("strips forbidden headers", () => {
    for (const h of [
      "Received:",
      "DKIM-Signature:",
      "Reply-To:",
      "X-Mailer:",
      "alice@gmail.com",
      "carol@corp.com",
    ]) {
      expect(headers).not.toContain(h);
    }
  });
  it("keeps threading headers inbound", () =>
    expect(headers).toContain("References: <prev@mail.gmail.com>"));
  it("regenerates Message-ID on relayDomain and stamps loop header", () => {
    expect(headers).toMatch(/Message-ID: <r\.[0-9a-f]{24}@relay\.example>/);
    expect(headers).toContain("X-Minister-Relay: stamp123");
  });
  it("prefixes [SPAM] when tagged", () => {
    const tagged = rewriteMessage({ ...inbound, tagSpam: true }).toString("utf8");
    expect(tagged).toContain("Subject: [SPAM] Hello");
  });
  it("encodes non-ASCII display names as RFC2047", () => {
    const utf = rewriteMessage({
      ...inbound,
      sender: { ...inbound.sender, displayName: "Ålice" },
    }).toString("utf8");
    expect(utf).toMatch(/From: =\?utf-8\?B\?[A-Za-z0-9+/=]+\?= <ra\./);
  });
});

describe("rewriteMessage outbound", () => {
  const out = rewriteMessage({
    kind: "outbound",
    raw: Buffer.from(RAW),
    relayDomain: "relay.example",
    aliasAddress: "tyler.x7k2qm@relay.example",
    lineDisplayName: "Tyler",
    toExternal: ["alice@gmail.com", "carol@corp.com"],
    loopStamp: "stamp123",
  }).toString("utf8");
  it("From is the alias with the line display name", () =>
    expect(out).toContain('From: "Tyler" <tyler.x7k2qm@relay.example>'));
  it("To lists resolved externals", () =>
    expect(out).toContain("To: alice@gmail.com, carol@corp.com"));
  it("drops threading headers outbound (slice-1 interim)", () => {
    expect(out).not.toContain("In-Reply-To:");
    expect(out).not.toContain("References:");
  });
  it("never emits Reply-To", () => expect(out).not.toContain("Reply-To:"));
});
```

- [ ] **Step 2: Run to verify failure** — `pnpm --filter @minister/relay-core test` → FAIL.

- [ ] **Step 3: Implement `src/rewrite.ts`.** Structure (complete the obvious bodies; no parsing library needed here — header surgery on the raw block):

```ts
import { randomBytes } from "node:crypto";

// ...interfaces from the block above...

// Split raw message into (headerBlock, bodyIncludingLeadingSeparator).
// Handles CRLF and bare-LF messages; output always uses the original body bytes.
function splitRaw(raw: Buffer): { header: string; body: Buffer } {
  const crlf = raw.indexOf("\r\n\r\n");
  const lf = raw.indexOf("\n\n");
  // pick whichever separator occurs first (and exists)
  // header = raw.slice(0, idx).toString("utf8"); body = raw.slice(idx + sepLen)
}

// Return the raw folded lines (verbatim, incl. continuations) for each named
// header present, in original order. Case-insensitive name match.
function pickRawHeaders(headerBlock: string, names: string[]): string[] {
  /* iterate physical lines; a line starting with space/tab continues the previous header */
}

// First value of a header, unfolded, or null.
function headerValue(headerBlock: string, name: string): string | null {
  /* ... */
}

function formatAddress(name: string | undefined, addr: string): string {
  if (!name) return addr;
  const clean = name.replace(/[\r\n"\\]/g, "").trim();
  if (!clean) return addr;
  const ascii = /^[\x20-\x7e]*$/.test(clean);
  const display = ascii
    ? `"${clean}"`
    : `=?utf-8?B?${Buffer.from(clean, "utf8").toString("base64")}?=`;
  return `${display} <${addr}>`;
}

const COPY_ALWAYS = [
  "Date",
  "MIME-Version",
  "Content-Type",
  "Content-Transfer-Encoding",
  "Content-Disposition",
  "Auto-Submitted",
];
const COPY_INBOUND_ONLY = ["In-Reply-To", "References"];

export function rewriteMessage(input: InboundRewriteInput | OutboundRewriteInput): Buffer {
  const { header, body } = splitRaw(input.raw);
  const out: string[] = [];

  if (input.kind === "inbound") {
    out.push(
      `From: ${formatAddress(viaName(input.sender.displayName, input.relayDomain), input.sender.reverseAliasAddress)}`,
    );
    out.push(`To: ${input.aliasAddress}`);
    if (input.others.length > 0)
      out.push(
        `Cc: ${input.others.map((p) => formatAddress(p.displayName, p.reverseAliasAddress)).join(", ")}`,
      );
  } else {
    out.push(`From: ${formatAddress(input.lineDisplayName, input.aliasAddress)}`);
    out.push(`To: ${input.toExternal.join(", ")}`);
  }

  const subject = headerValue(header, "Subject");
  if (subject !== null)
    out.push(
      `Subject: ${input.kind === "inbound" && input.tagSpam ? "[SPAM] " + subject : subject}`,
    );

  out.push(
    ...pickRawHeaders(
      header,
      input.kind === "inbound" ? [...COPY_ALWAYS, ...COPY_INBOUND_ONLY] : COPY_ALWAYS,
    ),
  );
  out.push(`Message-ID: <r.${randomBytes(12).toString("hex")}@${input.relayDomain}>`);
  out.push(`X-Minister-Relay: ${input.loopStamp}`);

  return Buffer.concat([Buffer.from(out.join("\r\n") + "\r\n\r\n", "utf8"), body]);
}

// "Alice Smith" -> "Alice Smith (via relay.example)"; undefined stays undefined.
function viaName(name: string | undefined, relayDomain: string): string | undefined {
  /* ... */
}
```

Implementation notes (constraints, not suggestions): `pickRawHeaders` must copy folded continuation lines byte-identically (the multipart boundary lives there). `Subject` goes through `headerValue` (single logical line) so the `[SPAM] ` prefix lands correctly even on folded subjects. Do NOT unfold or re-encode copied `Content-Type` lines. Body is `Buffer` end to end — never `.toString()` the body.

- [ ] **Step 4: Run tests until green** — `pnpm --filter @minister/relay-core test` PASS; `typecheck` clean.

- [ ] **Step 5: Commit**

```bash
git add packages/relay-core
git commit -m "feat(relay-core): allowlist header-rewrite engine for both relay directions"
```

---

### Task 5: Auth-results parsing + decision module — DOMAIN FLOOR

**Files:**

- Create: `packages/relay-core/src/auth-results.ts`, `packages/relay-core/src/decide.ts`
- Test: `packages/relay-core/src/auth-results.test.ts`, `packages/relay-core/src/decide.test.ts`
- Modify: `packages/relay-core/src/index.ts` (exports)

**Interfaces:**

- Produces (consumed by Task 6):

```ts
// auth-results.ts
export interface AuthVerdicts {
  spf: string;
  dkim: string;
  dmarc: string;
} // lowercase result tokens; "none" when absent
export function parseAuthResults(headerValues: string[]): AuthVerdicts;

// decide.ts
export interface LineCtx {
  id: string;
  ownerId: string;
  alias: string;
  status: string;
  deliveryAddress: string;
  displayName: string;
}
export interface ReverseCtx {
  id: string;
  lineId: string;
  localpart: string;
  externalAddress: string;
}
export interface MessageMeta {
  headerFromAddress: string | null;
  headerFromName?: string;
  envelopeFrom: string | null; // null = null sender <>
  auth: AuthVerdicts;
  spamVerdict: string;
  virusVerdict: string; // "PASS" | "FAIL" | "GRAY" | "UNKNOWN"
  sizeBytes: number;
  hasLoopStamp: boolean;
  autoSubmitted: boolean; // Auto-Submitted present and !== "no"
  receivedCount: number;
  toCc: { address: string; name?: string }[]; // all To+Cc header addresses
}
export interface Caps {
  maxSizeBytes: number;
  dailyOutboundCap: number;
  maxParticipants: number;
}
export type Decision =
  | {
      action: "forward-inbound";
      tagSpam: boolean;
      otherExternal: { address: string; name?: string }[];
    }
  | { action: "forward-outbound"; toExternal: string[] }
  | { action: "drop"; reason: string };
export function decideInbound(
  meta: MessageMeta,
  line: LineCtx,
  relayDomain: string,
  caps: Caps,
): Decision;
export function decideReply(
  meta: MessageMeta,
  reverse: ReverseCtx,
  line: LineCtx,
  siblingReverse: ReverseCtx[],
  outboundUsedToday: number,
  relayDomain: string,
  caps: Caps,
): Decision;
```

- [ ] **Step 1: Write failing tests.** `parseAuthResults`: extracts `spf=pass`/`dkim=fail`/`dmarc=pass` tokens from realistic `Authentication-Results` values (multiple headers, mixed case, missing methods → `"none"`). `decide.test.ts` — one test per rule, exact expected reasons:

| #   | scenario                                                           | expected                                                                           |
| --- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| 1   | `hasLoopStamp`                                                     | drop `loop`                                                                        |
| 2   | `virusVerdict: "FAIL"`                                             | drop `virus`                                                                       |
| 3   | `receivedCount: 30`                                                | drop `loop-suspect`                                                                |
| 4   | `sizeBytes > maxSizeBytes`                                         | drop `too-large` (bounce-note is slice 2)                                          |
| 5   | inbound, line `paused` / `revoked`                                 | drop `line-paused` / `line-revoked` (silent — spec Line-state semantics)           |
| 6   | inbound, active, `spamVerdict: "FAIL"`                             | forward-inbound `tagSpam: true`                                                    |
| 7   | inbound, toCc contains 2 externals + the alias itself              | `otherExternal` = the 2 externals only (relay-domain addresses excluded)           |
| 8   | inbound, toCc externals > `maxParticipants` (10)                   | drop `too-many-participants`                                                       |
| 9   | reply, `autoSubmitted: true` or `envelopeFrom: null`               | drop `auto-generated` (OOO containment)                                            |
| 10  | reply, `headerFromAddress !== line.deliveryAddress`                | drop `sender-mismatch`                                                             |
| 11  | reply, envelopeFrom domain ≠ headerFrom domain                     | drop `envelope-mismatch`                                                           |
| 12  | reply, `dmarc: "fail"`                                             | drop `sender-auth`                                                                 |
| 13  | reply, `dmarc: "none"` and `spf !== "pass"`                        | drop `sender-auth`                                                                 |
| 14  | reply, `outboundUsedToday >= dailyOutboundCap`                     | drop `quota`                                                                       |
| 15  | reply, line revoked/paused                                         | drop `line-revoked`/`line-paused`                                                  |
| 16  | reply, To contains 2 sibling reverse aliases                       | forward-outbound with BOTH resolved external addresses (group reply)               |
| 17  | reply, To contains an `ra.` localpart with NO matching sibling row | that recipient is silently omitted; if none resolve → drop `unknown-reverse-alias` |
| 18  | reply valid (dmarc pass)                                           | forward-outbound to `reverse.externalAddress`                                      |

- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement.** Rule order inside each function: loop → virus → received-count → size → line status → (inbound: spam-tag decision, participant extraction) / (reply: auto-generated → sender-From match (canonicalized) → envelope-domain match → DMARC-or-aligned-SPF → quota → resolve recipients from `[reverse, ...siblingReverse]` rows only). `parseAuthResults`: regex per method over joined header values, first match wins, lowercase, default `"none"`.
- [ ] **Step 4: Tests green + typecheck clean.**
- [ ] **Step 5: Commit** — `feat(relay-core): auth-results parser + forwarding decision rules`

---

### Task 6: relay-worker service (SQS→pipeline→SES)

**Files:**

- Modify: `pnpm-workspace.yaml` (add `- "services/*"` — the Rust service dirs have no package.json, pnpm ignores them)
- Create: `services/relay-worker/package.json`, `tsconfig.json`, `Dockerfile`, `src/env.ts`, `src/ports.ts`, `src/pipeline.ts`, `src/prisma-ports.ts`, `src/aws-ports.ts`, `src/main.ts`
- Test: `services/relay-worker/src/pipeline.test.ts`
- Modify: `docker-compose.yml` (relay-worker service under `profiles: ["relay"]`)

**Interfaces:**

- Consumes: everything Tasks 3–5 export; models from Task 2; spike result from Task 1 (verdict extraction path).
- Produces: running worker; `processMessage(ports, cfg, s3Key)` used by Task 7's main loop wiring.

- [ ] **Step 1: Package scaffold.**

`package.json` (deps pinned to the majors already in the repo where shared):

```json
{
  "name": "@minister/relay-worker",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "scripts": {
    "db:generate": "prisma generate --schema ../../apps/minister/prisma/schema.prisma",
    "dev": "tsx watch src/main.ts",
    "start": "tsx src/main.ts",
    "test": "vitest run",
    "typecheck": "tsc --noEmit",
    "postinstall": "pnpm run db:generate"
  },
  "dependencies": {
    "@aws-sdk/client-s3": "^3.700.0",
    "@aws-sdk/client-sesv2": "^3.700.0",
    "@aws-sdk/client-sqs": "^3.700.0",
    "@minister/relay-core": "workspace:*",
    "@prisma/client": "^6.0.1",
    "mailparser": "^3.7.1",
    "zod": "^3.24.1"
  },
  "devDependencies": {
    "@types/mailparser": "^3.4.5",
    "@types/node": "^22.10.2",
    "prisma": "^6.0.1",
    "tsx": "^4.19.2",
    "typescript": "^5.6.3",
    "vitest": "^3.2.6"
  }
}
```

`src/env.ts` — zod schema, fail-closed at boot: `RELAY_HOSTED_DOMAIN`, `RELAY_S3_BUCKET`, `RELAY_INBOUND_QUEUE_URL`, `RELAY_EVENTS_QUEUE_URL`, `RELAY_MASTER_SECRET` (min 32 chars), `RELAY_MAX_SIZE_BYTES` (default 26_214_400), `RELAY_DAILY_OUTBOUND_CAP` (default 200), `RELAY_MAX_PARTICIPANTS` (default 10), `AWS_REGION` (default `us-east-2`), `DATABASE_URL`. Loop stamp = `createHmac("sha256", RELAY_MASTER_SECRET).update("loop-stamp-v1").digest("hex").slice(0, 32)` computed once.

- [ ] **Step 2: Define ports (`src/ports.ts`)** — the DI seam that makes the pipeline testable without AWS or Postgres:

```ts
export interface AwsPorts {
  getObject(key: string): Promise<Buffer>;
  deleteObject(key: string): Promise<void>;
  sendRaw(raw: Buffer, from: string, to: string[]): Promise<string>; // returns SES messageId; uses config set
}
export interface DbPorts {
  findLineByAlias(alias: string): Promise<(LineCtx & {}) | null>;
  findReverseByLocalpart(localpart: string): Promise<{ reverse: ReverseCtx; line: LineCtx } | null>;
  siblingReverseAliases(lineId: string): Promise<ReverseCtx[]>;
  upsertReverseAlias(
    lineId: string,
    externalAddress: string,
    externalName: string | undefined,
    mintLocalpart: () => string,
  ): Promise<ReverseCtx>;
  insertLogProcessing(
    lineId: string,
    direction: "inbound" | "outbound",
    sesMessageId: string,
    sizeBytes: number,
    verdicts: { spam: string; virus: string },
  ): Promise<{ duplicate: boolean; logId: string | null }>;
  finishLog(
    logId: string,
    status: "forwarded" | "dropped",
    opts: { dropReason?: string; sentMessageId?: string; latencyMs: number },
  ): Promise<void>;
  bumpLineCounters(lineId: string, kind: "forwarded-inbound" | "dropped"): Promise<void>;
  outboundCountSince(ownerId: string, since: Date): Promise<number>;
}
```

`insertLogProcessing` implementation catches Prisma `P2002` on `sesMessageId` → `{ duplicate: true, logId: null }` (idempotency: at-least-once SQS delivery). `upsertReverseAlias` uses the `@@unique([lineId, externalAddress])` compound key; on create it calls `mintLocalpart()` and retries once on a `localpart` collision.

- [ ] **Step 3: Write failing pipeline tests** (`src/pipeline.test.ts`) with in-memory stub ports. Scenarios: (a) inbound to active alias → sendRaw called once, From/To assertions on the produced buffer, log finished `forwarded` with latencyMs, S3 object deleted, reverse aliases upserted for sender + CC'd external; (b) duplicate sesMessageId → no send, no delete... **correction: delete IS called** (message already handled; leaving the object undeletes storage-free) — assert delete called, send not; (c) inbound to revoked line → dropped log, counter bumped, delete called, no send; (d) reply from the line's delivery address with dmarc=pass → outbound send to reverse externalAddress, From = alias; (e) reply From a different address → drop `sender-mismatch`, no send; (f) unknown recipient localpart entirely (no line, no reverse) → delete + no log (unroutable — count nothing, there is no line to attribute to).

- [ ] **Step 4: Implement `src/pipeline.ts`.** Verdict extraction per the Task 1 spike: primary path reads `X-SES-Spam-Verdict` / `X-SES-Virus-Verdict` and `Authentication-Results` headers off the parsed message (`simpleParser(raw)` → `parsed.headers`); envelope data (`envelopeFrom`, recipients) from the `Return-Path` header S3 objects carry + parsed To/Cc — if the spike showed SNS-only verdicts, the SQS message body carries the `receipt` object instead; keep extraction in one function `extractMeta(raw, sqsBody): MessageMeta` so the switch is local. Then: classify first relay-domain recipient localpart → `decideInbound`/`decideReply` → on forward: upsert reverse aliases, `rewriteMessage`, `sendRaw` (inbound: to line.deliveryAddress; outbound: to decision.toExternal), `finishLog`, `deleteObject`. Every terminal path deletes the S3 object; only a thrown error (SES/DB down) leaves it for SQS redelivery.

- [ ] **Step 5: Tests green.** `pnpm --filter @minister/relay-worker test` PASS; `typecheck` clean (after `pnpm install` at root picks up the new workspace member and `db:generate` runs).

- [ ] **Step 6: `src/main.ts` + Dockerfile + compose.** main: validate env, construct real ports (`aws-ports.ts` with the three SDK clients — `sendRaw` = `SendEmailCommand({ Content: { Raw: { Data } }, ConfigurationSetName: "minister-relay", Destination: { ToAddresses }, FromEmailAddress })`; `prisma-ports.ts` over the generated client), long-poll `relay-inbound` (WaitTimeSeconds 20, MaxNumberOfMessages 5), for each message parse the S3 event JSON → `processMessage` per record → delete SQS message on success; concurrency 1 (spec: 2GB box). SIGTERM: stop polling, drain in-flight, exit. Log line ids + reasons ONLY. Dockerfile: `node:20-alpine`, pnpm, workspace install filtered to `@minister/relay-worker...`, CMD `pnpm --filter @minister/relay-worker start`. Compose service: `build: { context: ., dockerfile: services/relay-worker/Dockerfile }`, `profiles: ["relay"]`, env passthrough for the RELAY__/AWS__ set, `DATABASE_URL` pointing at the compose postgres.

- [ ] **Step 7: Commit** — `feat(relay-worker): SQS->rewrite->SES relay worker with port-injected pipeline`

---

### Task 7: Bounce/complaint auto-pause consumer

**Files:**

- Create: `services/relay-worker/src/events.ts`
- Test: `services/relay-worker/src/events.test.ts`
- Modify: `services/relay-worker/src/main.ts` (second poll loop), `src/ports.ts` (+`DbPorts.pauseLineForEvent`)

**Interfaces:**

- Consumes: SESv2 event JSON (SNS-wrapped) from `relay-events` queue; `LineMessageLog.sentMessageId` written by Task 6.
- Produces: `handleSesEvent(db, eventJson): Promise<void>`.

- [ ] **Step 1: Failing tests**: (a) `Complaint` event whose `mail.messageId` matches a log row's `sentMessageId` → line status flips to `paused`, `AuditLog` row `RELAY_LINE_AUTOPAUSED` with `{ lineId, cause: "complaint" }`; (b) `Bounce` with `bounceType: "Permanent"` → same with cause `bounce`; (c) transient bounce → no change; (d) unknown messageId → no-op, no throw; (e) already-revoked line → untouched.
- [ ] **Step 2: Implement.** `pauseLineForEvent(sentMessageId, cause)` in `DbPorts`/`prisma-ports`: one transaction — find log by `sentMessageId` (include line), `updateMany({ where: { id: lineId, status: "active" }, data: { status: "paused" } })`, insert `AuditLog` (userId = line.ownerId). Unwrap SNS envelope (`Message` field is the stringified SES event). Wire the second poll loop in main.
- [ ] **Step 3: Tests green, typecheck clean.**
- [ ] **Step 4: Commit** — `feat(relay-worker): bounce/complaint events auto-pause offending lines`

---

### Task 8: Line server actions (mint / pause / resume / cut)

**Files:**

- Create: `apps/minister/src/server/line-actions.ts`
- Test: `apps/minister/src/server/line-actions.test.ts`
- Modify: `apps/minister/package.json` (add `"@minister/relay-core": "workspace:*"` dependency)

**Interfaces:**

- Consumes: `isValidAliasPrefix`, `mintAliasLocalpart` from relay-core; `requireSession` (`@/lib/session`), `audit` (`@/lib/audit`), `prisma`, `createRateLimiter`.
- Produces (consumed by Task 9): `mintLine(input): Promise<MintLineResult>`, `pauseLine(lineId)`, `resumeLine(lineId)`, `revokeLine(lineId)` — all `"use server"`, all `revalidatePath("/lines")`.

- [ ] **Step 1: Failing tests** (mock `@/lib/prisma`, `@/lib/session`, `@/lib/audit` with `vi.mock`, mirroring the mocking style of `apps/minister/src/server/badge-actions.test.ts` — read it first and keep the same shape). Cases: mint happy path returns `{ ok: true, alias }` matching `/^myprefix\.[a-z2-9]{6}@relay\.example$/` and audits `LINE_MINTED` with `{ lineId, label }` (no alias, no delivery address in metadata); mint rejects: invalid prefix, missing `RELAY_HOSTED_DOMAIN` (`relay not configured` — fail closed like FreedInk's unset-OIDC pattern), deliveryEmail not owned / not verified / quarantined; unique-collision on `alias` insert retries up to 3 times then errors; per-user limiter (30 mints / 24h, key = userId) returns `{ ok: false, error: "rate_limited" }`; pause/resume/cut enforce ownership, `revoked` is terminal (resume on revoked → error), each audits (`LINE_PAUSED`/`LINE_RESUMED`/`LINE_REVOKED`), revoke sets `revokedAt`.

- [ ] **Step 2: Implement** following the `share-actions.ts` conventions exactly (zod `safeParse`, `requireSession()`, discriminated result types, `revalidatePath`). Input schema:

```ts
const MintInput = z.object({
  prefix: z.string().min(1).max(20),
  label: z.string().min(1).max(80),
  displayName: z.string().min(1).max(80),
  deliveryEmailId: z.string().cuid(),
});
```

Delivery-email guard in one query: `prisma.userEmail.findFirst({ where: { id, userId: session.user.id, verifiedAt: { not: null }, status: "active" } })`.

- [ ] **Step 3: Tests green** — `pnpm --filter @minister/app exec vitest run src/server/line-actions.test.ts`; `pnpm --filter @minister/app typecheck` clean.
- [ ] **Step 4: Commit** — `feat(lines): mint/pause/resume/revoke server actions`

---

### Task 9: /lines wallet page

**Files:**

- Create: `apps/minister/src/app/lines/page.tsx`, `apps/minister/src/components/lines-client.tsx`
- Modify: the site header nav (grep for the component that links `/shares` — `rg -l '"/shares"' apps/minister/src` — add a `/lines` link beside it)

**Interfaces:**

- Consumes: Task 8 actions; `getCurrentSession` (NOT raw `auth()`); existing `src/components/ui/*` primitives (Button, Card, Input — reuse, don't invent).

- [ ] **Step 1: Server component `page.tsx`**: `requireSession()`; fetch `prisma.line.findMany({ where: { ownerId }, orderBy: { createdAt: "desc" } })` + the user's verified emails; map to a plain `LineView` object (`{ id, alias, label, status, inboundCount, droppedCount, lastInboundAt: string | null, createdAt: string }`) at the RSC seam (dates → ISO strings; the server→client boundary is JSON-only, see CLAUDE.md). Render `<LinesClient lines={views} deliveryEmails={emailViews} hostedDomain={process.env.RELAY_HOSTED_DOMAIN ?? null} />`. When `hostedDomain` is null render the not-configured empty state instead of the mint form.
- [ ] **Step 2: Client component `lines-client.tsx`**: mint form (prefix, label, display name — REQUIRED with helper text "shown to people you write to; your account name is never used", delivery email select), calls `mintLine`, shows the new alias with a copy button. Line list rows: alias (mono, copy button), label, status badge, inbound/dropped counts, `lastInboundAt`, and per-status actions (active → Pause/Cut; paused → Resume/Cut; revoked → row grayed, no actions). Cut is a destructive confirm ("Cutting a line is permanent. Mail to this alias will be silently dropped.").
- [ ] **Step 3: Verify** — `pnpm --filter @minister/app typecheck && pnpm --filter @minister/app lint` clean; manual: `pnpm dev`, sign in, mint a line against a dev `RELAY_HOSTED_DOMAIN=relay.local`, pause/resume/cut it, confirm audit rows in `/admin` audit viewer.
- [ ] **Step 4: Commit** — `feat(lines): /lines wallet page with quick-mint and line management`

---

### Task 10: Live end-to-end verification (real AWS, real mailboxes)

**Files:**

- Create: `services/relay-worker/E2E-CHECK.md`, `services/relay-worker/scripts/header-check.ts`

**Interfaces:**

- Consumes: everything; Task 1 infra must be live and SES production access granted (or both test mailboxes verified as SES identities while still sandboxed — the runbook covers this variant).

- [ ] **Step 1: `header-check.ts`** — CLI: `tsx scripts/header-check.ts <message.eml> <forbidden1> <forbidden2> ...`. Reads the raw file, splits the header block, exits 1 listing every occurrence of: any forbidden string (the real addresses under test), or any header outside the spec allowlist+regenerated set. Exits 0 with `HEADERS CLEAN`.
- [ ] **Step 2: `E2E-CHECK.md`** — scripted walkthrough of the spec's slice-1 verification section: two real mailboxes (Gmail + one non-Google); mint a line; external → alias → confirm delivery, download raw ("Show original"), run header-check with both real addresses as forbidden strings; reply from the delivery mailbox → confirm external receives From the alias, raw checked likewise; group: CC a third mailbox inbound, reply-all, verify both received via reverse aliases and header-check passes on both; revoke → send again → confirm silent drop + `droppedCount` increment + "N dropped" visible on /lines; spoof test: from an unrelated mailbox, send to the reverse alias directly → confirm drop `sender-mismatch` in `LineMessageLog`; latency: `LineMessageLog.latencyMs` p50 < 10s over ≥5 messages.
- [ ] **Step 3: Execute the runbook**, paste results (redacting real addresses) into a "## Results <date>" section.
- [ ] **Step 4: Commit** — `test(relay): live e2e verification runbook + header allowlist checker`

---

## Post-plan gates (not tasks — release blockers)

1. **Auditor review (Fable), REQUIRED before exposing the relay to anyone but Tyler:** scope = Tasks 4–7 diff + spec "Double-blind protocol" / "Abuse controls" as the checklist; adversarial focus: header leaks the allowlist misses, reverse-alias spoofing, quota bypass, log hygiene.
2. SES production access confirmed (Task 1) — until then everything runs sandboxed against verified test mailboxes.
3. Prod deploy wiring (lightsail compose + SSM params for `RELAY_*`) is deliberately OUT of this plan — separate ops change, and note the known infra-repo compose drift before touching it.
