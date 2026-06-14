import Link from "next/link";
import { redirect } from "next/navigation";

import { auth } from "@/auth";
import { findVerifiedBadge } from "@/lib/vc";

// Gated page — a fake "private beta" that only admits users holding a
// Minister invite-code badge. The RP enforces this server-side by
// verifying the disclosed VC's signature against Minister's JWKS; the
// user merely *claiming* to be invited isn't enough.
export default async function PrivateBetaPage() {
  const session = await auth();
  if (!session?.user) redirect("/");

  const vc = await findVerifiedBadge(
    session.ministerBadges ?? [],
    "invite-code",
  );

  if (!vc) {
    const issuer =
      process.env.MINISTER_ISSUER_URL?.replace(/\/$/, "") ??
      "http://localhost:3000";
    return (
      <main className="mx-auto flex max-w-xl flex-col gap-4 px-4 py-12">
        <h1 className="text-2xl font-semibold tracking-tight">
          Sorry — this beta is invite-only.
        </h1>
        <p className="text-sm text-neutral-600">
          This page requires a Minister-issued invite-code credential.
          Either you haven&apos;t redeemed an invite in Minister, or you
          didn&apos;t disclose it on the consent screen when you signed in.
        </p>
        <div className="flex gap-2">
          <a
            href={`${issuer}/badges/new/invite-code`}
            className="rounded-md bg-neutral-900 px-4 py-2 text-sm font-medium text-white hover:bg-neutral-900/90"
          >
            Redeem an invite in Minister
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

  const label =
    typeof vc.vc.credentialSubject.label === "string"
      ? vc.vc.credentialSubject.label
      : "the beta";

  return (
    <main className="mx-auto flex max-w-xl flex-col gap-4 px-4 py-12">
      <h1 className="text-2xl font-semibold tracking-tight">
        Welcome to the private beta. 🎉
      </h1>
      <p className="text-sm text-neutral-600">
        Verified your invite-code credential against Minister&apos;s signing
        key. You were invited to{" "}
        <span className="font-medium">{label}</span> — access granted.
      </p>
      <div className="rounded-lg border border-neutral-200 bg-white p-4 text-xs">
        <div>
          cohort: <code>{label}</code>
        </div>
        <div>
          issuer: <code>{vc.iss}</code>
        </div>
        <div>
          subject: <code>{vc.sub}</code>
        </div>
        {vc.exp ? (
          <div>expires: {new Date(vc.exp * 1000).toISOString()}</div>
        ) : null}
      </div>
      <Link href="/" className="text-sm underline">
        ← back
      </Link>
    </main>
  );
}
