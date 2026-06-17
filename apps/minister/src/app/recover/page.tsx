import Link from "next/link";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

// Unauthenticated account-recovery landing. Both paths land a reduced-
// capability, quarantined session: enough to enroll a fresh passkey, never a
// full takeover (see DESIGNDECISIONS #9). The credential-threshold path only
// helps users who accrued re-provable badges; recovery codes are the universal
// cold-start backstop.
const RECOVERY_PATHS = [
  {
    href: "/recover/codes",
    title: "Use a recovery code",
    description:
      "Enter your email and one of the single-use recovery codes you saved when you set up your account.",
  },
  {
    href: "/recover/badges",
    title: "Re-prove your credentials",
    description:
      "Recover by re-proving enough of the credentials you verified before (a passport-backed proof counts far more than a social login).",
  },
];

export default function RecoverPage() {
  return (
    <div className="mx-auto flex max-w-xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Recover your account</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Lost your passkey or your email? Choose how to prove this account is yours. Either way you
          will land in a limited session and be prompted to enroll a new passkey.
        </p>
      </header>

      {RECOVERY_PATHS.map((path) => (
        <Card key={path.href}>
          <CardHeader>
            <CardTitle>
              <Link href={path.href} className="hover:underline">
                {path.title}
              </Link>
            </CardTitle>
            <CardDescription>{path.description}</CardDescription>
          </CardHeader>
          <CardContent>
            <Link
              href={path.href}
              className="text-sm font-medium text-emerald-700 hover:underline dark:text-emerald-400"
            >
              Continue &rarr;
            </Link>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
