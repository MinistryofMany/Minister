import Link from "next/link";

import { Button } from "@/components/ui/button";
import { getCurrentSession } from "@/lib/session";

export async function Header() {
  // Same reason as the home page: a stale JWT shouldn't render the
  // signed-in nav (which links to /profile, where the user would be
  // bounced back out anyway). React.cache() in getCurrentSession
  // de-dupes the DB read across header + page in the same request.
  const session = await getCurrentSession();
  const signedIn = Boolean(session?.user);

  return (
    <header className="border-b border-neutral-200 bg-white/80 backdrop-blur dark:border-neutral-800 dark:bg-neutral-950/80">
      <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-4">
        <Link href="/" className="font-semibold tracking-tight">
          Tessera
        </Link>
        <nav className="flex items-center gap-2 text-sm">
          {signedIn ? (
            <>
              <Button asChild variant="ghost" size="sm">
                <Link href="/profile">Profile</Link>
              </Button>
              <Button asChild variant="ghost" size="sm">
                <Link href="/settings">Settings</Link>
              </Button>
            </>
          ) : (
            <Button asChild variant="ghost" size="sm">
              <Link href="/">Sign in</Link>
            </Button>
          )}
        </nav>
      </div>
    </header>
  );
}
