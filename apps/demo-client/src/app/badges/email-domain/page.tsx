import Link from "next/link";
import { redirect } from "next/navigation";

import { auth } from "@/auth";
import { findVerifiedBadge } from "@/lib/vc";

// Gated page — requires a verified email-domain VC. The RP enforces
// this server-side by checking the VCs Minister disclosed; "the user
// said they have one" isn't enough, we verify the signature against
// Minister's JWKS.
export default async function GatedPage() {
  const session = await auth();
  if (!session?.user) redirect("/");

  const vc = await findVerifiedBadge(session.ministerBadges ?? [], "email-domain");

  if (!vc) {
    const issuer = process.env.MINISTER_ISSUER_URL?.replace(/\/$/, "") ?? "http://localhost:3000";
    return (
      <main className="mx-auto flex max-w-xl flex-col gap-4 px-4 py-12">
        <h1 className="text-2xl font-semibold tracking-tight">
          You don&apos;t have an email-domain badge.
        </h1>
        <p className="text-sm text-neutral-600">
          This page requires a Minister-issued credential proving control of an email address at
          some domain. Either you haven&apos;t claimed one in Minister, or you didn&apos;t disclose
          it at the consent screen.
        </p>
        <div className="flex gap-2">
          <a
            href={`${issuer}/badges/new/email-domain`}
            className="rounded-md bg-neutral-900 px-4 py-2 text-sm font-medium text-white hover:bg-neutral-900/90"
          >
            Claim one in Minister
          </a>
          <Link
            href="/"
            className="rounded-md border border-neutral-300 px-4 py-2 text-sm font-medium hover:bg-neutral-50"
          >
            Back
          </Link>
        </div>
      </main>
    );
  }

  const domain =
    typeof vc.vc.credentialSubject.domain === "string" ? vc.vc.credentialSubject.domain : "unknown";

  return (
    <main className="mx-auto flex max-w-xl flex-col gap-4 px-4 py-12">
      <h1 className="text-2xl font-semibold tracking-tight">Welcome, {domain} resident.</h1>
      <p className="text-sm text-neutral-600">
        Verified your email-domain credential against Minister&apos;s signing key. Specifically: you
        control an email at <span className="font-medium">{domain}</span>.
      </p>
      <div className="rounded-lg border border-neutral-200 bg-white p-4 text-xs">
        <div>
          issuer: <code>{vc.iss}</code>
        </div>
        <div>
          subject: <code>{vc.sub}</code>
        </div>
        {vc.exp ? <div>expires: {new Date(vc.exp * 1000).toISOString()}</div> : null}
      </div>
      <Link href="/" className="text-sm underline">
        ← back
      </Link>
    </main>
  );
}
