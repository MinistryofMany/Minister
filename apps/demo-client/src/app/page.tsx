import Link from "next/link";

import { auth, signIn, signOut } from "@/auth";

export default async function HomePage() {
  const session = await auth();
  const signedIn = Boolean(session?.user);

  return (
    <main className="mx-auto flex max-w-xl flex-col gap-6 px-4 py-16">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">Minister Demo Client</h1>
        <p className="text-sm text-neutral-600">
          Sample relying party. Uses Minister as an OpenID Connect identity provider, requests a few
          scopes, and gates one of its pages on a specific badge.
        </p>
      </header>

      {signedIn ? (
        <section className="rounded-lg border border-neutral-200 bg-white p-6">
          <h2 className="text-lg font-semibold">Signed in via Minister</h2>
          <p className="mt-1 text-sm text-neutral-600">
            sub: <code className="text-xs">{session?.ministerSub}</code>
            <br />
            badges disclosed: {session?.ministerBadges?.length ?? 0}
          </p>
          <div className="mt-4 flex flex-wrap gap-3">
            <Link
              href="/me"
              className="rounded-md bg-neutral-900 px-4 py-2 text-sm font-medium text-white hover:bg-neutral-900/90"
            >
              Inspect tokens
            </Link>
            <Link
              href="/private-beta"
              className="rounded-md border border-neutral-300 px-4 py-2 text-sm font-medium hover:bg-neutral-50"
            >
              Enter private beta (needs invite badge)
            </Link>
            <Link
              href="/badges/email-domain"
              className="rounded-md border border-neutral-300 px-4 py-2 text-sm font-medium hover:bg-neutral-50"
            >
              Email-domain gated page
            </Link>
            <form
              action={async () => {
                "use server";
                await signOut({ redirectTo: "/" });
              }}
            >
              <button
                type="submit"
                className="rounded-md border border-neutral-300 px-4 py-2 text-sm font-medium hover:bg-neutral-50"
              >
                Sign out (here)
              </button>
            </form>
          </div>
        </section>
      ) : (
        <section className="rounded-lg border border-neutral-200 bg-white p-6">
          <h2 className="text-lg font-semibold">Sign in with Minister</h2>
          <p className="mt-1 text-sm text-neutral-600">
            You&apos;ll be redirected to Minister to authenticate, then back here. Minister shows a
            consent screen where you choose exactly which badges to disclose.
          </p>
          <form
            className="mt-4"
            action={async () => {
              "use server";
              await signIn("minister", { redirectTo: "/me" });
            }}
          >
            <button
              type="submit"
              className="rounded-md bg-neutral-900 px-4 py-2 text-sm font-medium text-white hover:bg-neutral-900/90"
            >
              Sign in with Minister
            </button>
          </form>
        </section>
      )}

      <footer className="text-xs text-neutral-500">
        Minister issuer: <code>{process.env.MINISTER_ISSUER_URL ?? "http://localhost:3000"}</code>
      </footer>
    </main>
  );
}
