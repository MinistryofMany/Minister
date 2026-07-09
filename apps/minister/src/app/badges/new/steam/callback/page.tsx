import { headers } from "next/headers";
import Link from "next/link";
import { redirect } from "next/navigation";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getCurrentSession } from "@/lib/session";
import { resumeViaPendingToken } from "@/server/wizard";

// Steam OpenID 2.0 returns a flat set of openid.* params plus our own `state`
// (which we tucked into return_to). searchParams therefore has open-ended keys.
interface PageProps {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

// Pull just the openid.* params (as strings) out of the callback query for the
// check_authentication post-back.
function collectOpenidParams(
  params: Record<string, string | string[] | undefined>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(params)) {
    if (key.startsWith("openid.") && typeof value === "string") {
      out[key] = value;
    }
  }
  return out;
}

// Steam redirects the user here after the OpenID sign-in. We resolve the
// in-flight wizard session via ?state (the runtime's pendingToken), then hand
// the full openid.* set to the plugin for verification.
export default async function SteamCallbackPage({ searchParams }: PageProps) {
  const params = await searchParams;
  const session = await getCurrentSession();

  if (!session?.user) {
    return (
      <Shell title="Sign in to finish">
        <CardDescription>
          You came back from Steam but aren&apos;t signed in to Minister here. Sign in (same
          browser) and then re-run the Steam flow.
        </CardDescription>
        <Button asChild className="mt-4 self-start">
          <Link href="/">Go to sign-in</Link>
        </Button>
      </Shell>
    );
  }

  const state = typeof params.state === "string" ? params.state : undefined;
  const openid = collectOpenidParams(params);

  if (!state || Object.keys(openid).length === 0) {
    return (
      <Shell title="Malformed callback">
        <CardDescription>
          Steam redirected without the expected sign-in data. The flow may have expired — restart
          it.
        </CardDescription>
        <Button asChild variant="outline" className="mt-4 self-start">
          <Link href="/badges/new/steam">Restart</Link>
        </Button>
      </Shell>
    );
  }

  const h = await headers();
  const origin = `${h.get("x-forwarded-proto") ?? "http"}://${h.get("host") ?? "localhost:3000"}`;

  const result = await resumeViaPendingToken({
    token: state,
    userId: session.user.id,
    origin,
    input: { openid },
  });

  if (result.kind === "complete") {
    redirect("/profile?issued=steam");
  }

  if (result.kind === "continue") {
    redirect(`/badges/new/${result.pluginId}?wsid=${encodeURIComponent(result.sessionId)}`);
  }

  return (
    <Shell title="Steam flow failed">
      <CardDescription>{result.message}</CardDescription>
      <Button asChild variant="outline" className="mt-4 self-start">
        <Link href="/badges/new/steam">Restart</Link>
      </Button>
    </Shell>
  );
}

function Shell({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mx-auto flex max-w-md flex-col gap-6 px-4 py-12">
      <Card>
        <CardHeader>
          <CardTitle>{title}</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col">{children}</CardContent>
      </Card>
    </div>
  );
}
