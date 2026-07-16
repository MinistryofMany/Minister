"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState, useTransition } from "react";

import { EnrollmentFlow } from "@/components/anon-seed/enrollment-flow";
import { PasskeyProtectButton } from "@/components/anon-seed/passkey-protect-button";
import { PmSave } from "@/components/anon-seed/pm-save";
import { UnlockPanel } from "@/components/anon-seed/unlock-panel";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  getMemoryOnlyPref,
  isVaultReady,
  lockVault,
  setMemoryOnlyPref,
} from "@/lib/anon-seed/vault";
import { deleteSeedBlob, resetAnonSeed, type AnonSeedStatus } from "@/server/anon-seed-actions";

// Lifecycle surface for the anonymous key (spec §6.2 proactive enrollment,
// §7 storage layers, §6.1 reset). All key material stays in the client vault;
// this page only drives it and the metadata-only server actions.

interface PasskeyBlobItem {
  credentialId: string;
  createdAt: string;
}

export function AnonymousKeyManager({
  userId,
  initialStatus,
  passkeyBlobs,
  epoch,
}: {
  userId: string;
  initialStatus: AnonSeedStatus;
  passkeyBlobs: PasskeyBlobItem[];
  // Server-snapshotted enrollment epoch; threaded into the unlock path (Lane C).
  epoch: number;
}) {
  const router = useRouter();
  const [status, setStatus] = useState<AnonSeedStatus>(initialStatus);
  const [unlocked, setUnlocked] = useState(() => isVaultReady(userId));
  // localStorage resolves after mount so SSR HTML and hydration agree.
  const [memoryOnly, setMemoryOnly] = useState(false);
  useEffect(() => {
    setMemoryOnly(getMemoryOnlyPref(userId));
  }, [userId]);

  if (status !== "active") {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Set up your Private Identity</CardTitle>
          <CardDescription>
            Takes about a minute. You&apos;ll back it up and prove you did.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <EnrollmentFlow
            userId={userId}
            needsRestart={status === "pending_backup"}
            onComplete={() => {
              setStatus("active");
              setUnlocked(isVaultReady(userId));
              router.refresh();
            }}
          />
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Status</CardTitle>
          <CardDescription>
            Your Private Identity is set up and backed up. It unlocks in your browser when an app
            asks for your anonymous identity.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {unlocked ? (
            <p className="text-sm font-medium text-green-700 dark:text-green-400">
              Unlocked on this page.
            </p>
          ) : (
            <UnlockPanel
              userId={userId}
              hasPasskeyBlobs={passkeyBlobs.length > 0}
              epoch={epoch}
              onUnlocked={() => setUnlocked(true)}
            />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Where it&apos;s kept</CardTitle>
          <CardDescription>
            Encrypted passkey copies Ministry cannot read, and your browser&apos;s password manager.
            Your written backup always works.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {passkeyBlobs.length > 0 ? (
            <ul className="flex flex-col gap-2">
              {passkeyBlobs.map((b) => (
                <PasskeyBlobRow key={b.credentialId} blob={b} onDeleted={() => router.refresh()} />
              ))}
            </ul>
          ) : (
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              No passkey-protected copies yet.
            </p>
          )}

          {memoryOnly ? (
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              Storage is off — you&apos;ve chosen to re-enter your Private Identity every session.
            </p>
          ) : unlocked ? (
            <div className="flex flex-col gap-3">
              <PasskeyProtectButton userId={userId} onStored={() => router.refresh()} />
              <PmSave userId={userId} />
            </div>
          ) : (
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              Unlock your Private Identity above to add a passkey copy or save it to your password
              manager.
            </p>
          )}

          <label className="flex items-start gap-3 rounded-md border border-neutral-200 p-3 text-sm dark:border-neutral-800">
            <input
              type="checkbox"
              className="mt-0.5 h-4 w-4"
              checked={memoryOnly}
              onChange={(e) => {
                setMemoryOnly(e.target.checked);
                setMemoryOnlyPref(userId, e.target.checked);
              }}
            />
            <span>
              <span className="block font-medium">Never store my Private Identity</span>
              <span className="text-neutral-600 dark:text-neutral-400">
                Skip passkey and password-manager storage. You&apos;ll enter your Private Identity
                (or pair a device) every browser session — that&apos;s the point.
              </span>
            </span>
          </label>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Use it on another device</CardTitle>
          <CardDescription>
            Move your Private Identity between your own devices with a QR code, like linking a chat
            app. Your key is sent end-to-end encrypted — Ministry never sees it.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 sm:flex-row">
          <Button asChild variant="outline">
            <Link href="/settings/private-identity/add-device">
              Add a device (I have my key here)
            </Link>
          </Button>
          <Button asChild variant="outline">
            <Link href="/settings/private-identity/get-key">Get my key from another device</Link>
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Lost your Private Identity?</CardTitle>
          <CardDescription>
            If you no longer have your key on any device, you can&apos;t recover it — but you can
            re-key: replace it with a new one and keep your account, badges, and memberships.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild variant="outline">
            <Link href="/settings/private-identity/rekey">I lost my key</Link>
          </Button>
        </CardContent>
      </Card>

      <ResetCard
        onReset={() => {
          lockVault();
          setStatus("none");
          setUnlocked(false);
          router.refresh();
        }}
      />
    </>
  );
}

function PasskeyBlobRow({ blob, onDeleted }: { blob: PasskeyBlobItem; onDeleted: () => void }) {
  const [pending, startTransition] = useTransition();
  return (
    <li className="flex items-center justify-between gap-3 rounded-md border border-neutral-200 p-3 dark:border-neutral-800">
      <div className="min-w-0">
        <div className="truncate font-mono text-xs text-neutral-600 dark:text-neutral-400">
          {blob.credentialId}
        </div>
        <div className="text-xs text-neutral-500">
          Passkey copy added {new Date(blob.createdAt).toLocaleDateString()}
        </div>
      </div>
      <Button
        type="button"
        variant="outline"
        size="sm"
        disabled={pending}
        onClick={() =>
          startTransition(async () => {
            await deleteSeedBlob({ credentialId: blob.credentialId });
            onDeleted();
          })
        }
      >
        {pending ? "Removing…" : "Remove"}
      </Button>
    </li>
  );
}

function ResetCard({ onReset }: { onReset: () => void }) {
  const [phrase, setPhrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  return (
    <Card className="border-red-200 dark:border-red-900/40">
      <CardHeader>
        <CardTitle>Reset your Private Identity</CardTitle>
        <CardDescription>
          Destructive: a new Private Identity means a new, unrelated identity in every connected
          app. Your current anonymous identities become permanently unreachable.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        {error ? (
          <p className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-950/30 dark:text-red-400">
            {error}
          </p>
        ) : null}
        <label htmlFor="anon-reset-phrase" className="text-sm">
          Type <span className="font-mono font-medium">reset my anonymous key</span> to confirm.
        </label>
        <div className="flex gap-2">
          <Input
            id="anon-reset-phrase"
            value={phrase}
            onChange={(e) => setPhrase(e.target.value)}
            autoComplete="off"
            placeholder="reset my anonymous key"
          />
          <Button
            type="button"
            variant="destructive"
            disabled={pending || phrase.trim().length === 0}
            onClick={() =>
              startTransition(async () => {
                setError(null);
                const result = await resetAnonSeed({ confirmPhrase: phrase });
                if (!result.ok) {
                  setError(result.error);
                  return;
                }
                setPhrase("");
                onReset();
              })
            }
          >
            {pending ? "Resetting…" : "Reset"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
