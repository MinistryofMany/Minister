"use client";

import { useState, useTransition } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { signIn as signInWebAuthn } from "next-auth/webauthn";
import { KeyRound, Mail, ShieldCheck, Trash2, UserCircle } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  addEmailAction,
  canAddPasskeyAction,
  listCredentialsAction,
  markPasskeyEnrolledAction,
  removeEmailAction,
  removePasskeyAction,
  setPrimaryEmailAction,
  type ActionResult,
  type CredentialListing,
} from "@/server/credential-actions";

// Run a wrapped action; on a step-up result, run the passkey ceremony then
// retry ONCE. Returns the final non-step-up result, or null if the user
// abandoned/failed the step-up ceremony.
async function withStepUp<T>(
  call: () => Promise<ActionResult<T>>,
): Promise<ActionResult<T> | null> {
  const first = await call();
  if (first.ok || !("stepUp" in first) || !first.stepUp) {
    return first;
  }
  // Step-up: run a passkey assertion in place (redirect:false so we stay on
  // the page), then retry the action against the now-AAL2 session.
  try {
    const res = await signInWebAuthn("passkey", { redirect: false });
    if (res && "error" in res && res.error) {
      return null;
    }
  } catch {
    return null;
  }
  const retried = await call();
  // If it STILL wants step-up, the ceremony didn't raise the session — give up.
  if (!retried.ok && "stepUp" in retried && retried.stepUp) return null;
  return retried;
}

export function CredentialsManager({ initial }: { initial: CredentialListing }) {
  const router = useRouter();
  const [listing, setListing] = useState(initial);
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [newEmail, setNewEmail] = useState("");
  // Set to the colliding address when the user tries to add an email that
  // already belongs to another account. Drives the "combine accounts" offer.
  const [mergeOffer, setMergeOffer] = useState<string | null>(null);

  function reset() {
    setError(null);
    setNotice(null);
    setMergeOffer(null);
  }

  async function refresh() {
    const res = await listCredentialsAction();
    if (res.ok) setListing(res.data);
    router.refresh();
  }

  // Run an action through step-up, surface result, refresh on success.
  function dispatch<T>(
    call: () => Promise<ActionResult<T>>,
    onSuccess?: (data: T) => void,
    successNotice?: string,
  ) {
    reset();
    startTransition(async () => {
      const res = await withStepUp(call);
      if (res === null) {
        setError("Step-up with a passkey is required and was not completed.");
        return;
      }
      if (!res.ok) {
        if ("stepUp" in res && res.stepUp) {
          setError("This action requires a passkey. Add or use a passkey, then try again.");
        } else {
          setError(res.error);
        }
        return;
      }
      onSuccess?.(res.data);
      if (successNotice) setNotice(successNotice);
      await refresh();
    });
  }

  // addEmail is handled outside dispatch() because it has an extra outcome the
  // generic path can't express: a collision with an address already on another
  // account. On collision we surface a merge offer instead of a dead-end error.
  // We still run the step-up-then-retry-once dance for the AAL2 floor.
  function handleAddEmail(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const email = newEmail.trim();
    if (!email) return;
    reset();
    startTransition(async () => {
      let res = await addEmailAction(email);
      if (!res.ok && "stepUp" in res && res.stepUp) {
        try {
          const stepUp = await signInWebAuthn("passkey", { redirect: false });
          if (stepUp && "error" in stepUp && stepUp.error) {
            setError("Step-up with a passkey is required and was not completed.");
            return;
          }
        } catch {
          setError("Step-up with a passkey is required and was not completed.");
          return;
        }
        res = await addEmailAction(email);
      }
      if (res.ok) {
        setNewEmail("");
        setNotice("Verification email sent. Check that inbox to finish adding the address.");
        await refresh();
        return;
      }
      if ("collision" in res && res.collision) {
        setMergeOffer(res.email);
        return;
      }
      if ("stepUp" in res && res.stepUp) {
        setError("This action requires a passkey. Add or use a passkey, then try again.");
        return;
      }
      setError(res.error);
    });
  }

  // Passkey enrollment: gate on the bootstrap rule, run the WebAuthn register
  // ceremony, then finalize (lifecycle stamp + notify) through markPasskeyEnrolled.
  function handleAddPasskey() {
    reset();
    startTransition(async () => {
      const gate = await canAddPasskeyAction();
      if (!gate.ok) {
        if ("stepUp" in gate && gate.stepUp) {
          setError("Adding another passkey requires a passkey step-up first.");
        } else {
          setError(gate.error);
        }
        return;
      }
      if (!gate.data.allowed) {
        // Not a bootstrap and below AAL2 — step up, then enroll.
        try {
          const res = await signInWebAuthn("passkey", { redirect: false });
          if (res && "error" in res && res.error) {
            setError("Passkey step-up was not completed.");
            return;
          }
        } catch {
          setError("Passkey step-up was not completed.");
          return;
        }
      }

      // Run the registration ceremony.
      try {
        const res = await signInWebAuthn("passkey", { action: "register", redirect: false });
        if (res && "error" in res && res.error) {
          setError("Passkey enrollment was cancelled or failed.");
          return;
        }
      } catch {
        setError("Passkey enrollment was cancelled or failed.");
        return;
      }

      // Apply lifecycle + notify.
      const fin = await markPasskeyEnrolledAction();
      if (!fin.ok) {
        setError("stepUp" in fin && fin.stepUp ? "A passkey step-up is required." : fin.error);
        return;
      }
      setNotice(
        fin.data.quarantined
          ? "Passkey added. It's quarantined for a short window before it can manage other credentials."
          : "Passkey added.",
      );
      await refresh();
    });
  }

  return (
    <div className="flex flex-col gap-6">
      {error ? (
        <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-300">
          {error}
        </p>
      ) : null}
      {notice ? (
        <p className="rounded-md border border-green-200 bg-green-50 p-3 text-sm text-green-700 dark:border-green-900 dark:bg-green-950 dark:text-green-300">
          {notice}
        </p>
      ) : null}

      {/* Emails ------------------------------------------------------------ */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Mail className="h-5 w-5" /> Emails
          </CardTitle>
          <CardDescription>
            Any verified address can receive a sign-in link. Exactly one is your primary
            (notification) address.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {listing.emails.length === 0 ? (
            <p className="text-sm text-neutral-500">No emails on this account yet.</p>
          ) : (
            <ul className="flex flex-col divide-y divide-neutral-200 dark:divide-neutral-800">
              {listing.emails.map((e) => (
                <li key={e.id} className="flex items-center justify-between gap-3 py-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="truncate text-sm font-medium">{e.email}</span>
                      {e.isPrimary ? <Badge tone="primary">Primary</Badge> : null}
                      {e.verified ? (
                        <Badge tone="active">Verified</Badge>
                      ) : (
                        <Badge tone="pending">Unverified</Badge>
                      )}
                      {e.status === "quarantined" ? (
                        <Badge tone="quarantined">Quarantined</Badge>
                      ) : null}
                    </div>
                  </div>
                  <div className="flex shrink-0 gap-2">
                    {e.verified && !e.isPrimary ? (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        disabled={pending}
                        onClick={() =>
                          dispatch(
                            () => setPrimaryEmailAction(e.id),
                            undefined,
                            "Primary email updated.",
                          )
                        }
                      >
                        Make primary
                      </Button>
                    ) : null}
                    <Button
                      type="button"
                      size="sm"
                      variant="ghost"
                      disabled={pending}
                      onClick={() => {
                        if (
                          typeof window !== "undefined" &&
                          !window.confirm(`Remove ${e.email} from your account?`)
                        ) {
                          return;
                        }
                        dispatch(() => removeEmailAction(e.id), undefined, "Email removed.");
                      }}
                      aria-label={`Remove ${e.email}`}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </li>
              ))}
            </ul>
          )}

          <form onSubmit={handleAddEmail} className="flex flex-col gap-2 sm:flex-row">
            <Input
              type="email"
              placeholder="add another email"
              value={newEmail}
              onChange={(ev) => setNewEmail(ev.target.value)}
              disabled={pending}
            />
            <Button type="submit" variant="outline" disabled={pending || newEmail.trim() === ""}>
              Add email
            </Button>
          </form>

          {mergeOffer ? (
            <div className="flex flex-col gap-2 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-300">
              <p>
                <span className="font-medium">{mergeOffer}</span> already belongs to another
                Minister account, so it can&apos;t be added here. If that account is also yours, you
                can combine it into this one. You&apos;ll confirm you control that address first.
              </p>
              <div className="flex gap-2">
                <Button asChild size="sm">
                  <Link href={`/settings/merge?donor=${encodeURIComponent(mergeOffer)}`}>
                    Combine that account in
                  </Link>
                </Button>
                <Button type="button" size="sm" variant="ghost" onClick={() => setMergeOffer(null)}>
                  Not now
                </Button>
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>

      {/* Passkeys ---------------------------------------------------------- */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="h-5 w-5" /> Passkeys
          </CardTitle>
          <CardDescription>
            Phishing-resistant factors (AAL2). A passkey is required to make sensitive changes.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {listing.passkeys.length === 0 ? (
            <p className="text-sm text-neutral-500">
              No passkeys yet. Add one to secure your account.
            </p>
          ) : (
            <ul className="flex flex-col divide-y divide-neutral-200 dark:divide-neutral-800">
              {listing.passkeys.map((p) => (
                <li key={p.credentialID} className="flex items-center justify-between gap-3 py-3">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-neutral-500" />
                    <span className="text-sm font-medium">{p.label ?? "Passkey"}</span>
                    {p.status === "quarantined" ? (
                      <Badge tone="quarantined">Quarantined</Badge>
                    ) : (
                      <Badge tone="active">Active</Badge>
                    )}
                  </div>
                  <Button
                    type="button"
                    size="sm"
                    variant="ghost"
                    disabled={pending}
                    onClick={() => {
                      if (
                        typeof window !== "undefined" &&
                        !window.confirm("Remove this passkey?")
                      ) {
                        return;
                      }
                      dispatch(
                        () => removePasskeyAction(p.credentialID),
                        undefined,
                        "Passkey removed.",
                      );
                    }}
                    aria-label="Remove passkey"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </li>
              ))}
            </ul>
          )}
          <Button
            type="button"
            variant="outline"
            className="self-start"
            disabled={pending}
            onClick={handleAddPasskey}
          >
            Add a passkey
          </Button>
        </CardContent>
      </Card>

      {/* Linked accounts --------------------------------------------------- */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UserCircle className="h-5 w-5" /> Linked accounts
          </CardTitle>
          <CardDescription>OAuth providers connected to your account.</CardDescription>
        </CardHeader>
        <CardContent>
          {listing.accounts.length === 0 ? (
            <p className="text-sm text-neutral-500">No linked accounts.</p>
          ) : (
            <ul className="flex flex-col divide-y divide-neutral-200 dark:divide-neutral-800">
              {listing.accounts.map((a) => (
                <li
                  key={`${a.provider}:${a.providerAccountId}`}
                  className="flex items-center justify-between gap-3 py-3"
                >
                  <span className="text-sm font-medium capitalize">{a.label ?? a.provider}</span>
                  {a.status === "quarantined" ? (
                    <Badge tone="quarantined">Quarantined</Badge>
                  ) : (
                    <Badge tone="active">Active</Badge>
                  )}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      {listing.recovered ? (
        <p className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-300">
          You&apos;re in a recovery session. Add a passkey to restore full access — other credential
          changes are disabled until you do.
        </p>
      ) : null}
    </div>
  );
}

type BadgeTone = "active" | "primary" | "pending" | "quarantined";

const TONE: Record<BadgeTone, string> = {
  active: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300",
  primary: "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300",
  pending: "bg-neutral-100 text-neutral-600 dark:bg-neutral-800 dark:text-neutral-300",
  quarantined: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
};

function Badge({ tone, children }: { tone: BadgeTone; children: React.ReactNode }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${TONE[tone]}`}
    >
      {children}
    </span>
  );
}
