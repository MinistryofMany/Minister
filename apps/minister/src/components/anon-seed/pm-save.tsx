"use client";

import { useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  getSeedBackupString,
  passwordCredentialSupported,
  PM_CREDENTIAL_ID,
  savePasswordToManager,
} from "@/lib/anon-seed/vault";

// L2 storage offer (spec §7.2): save the key string in the browser password
// manager. Governing rule (I11): the seed must NEVER sit in a form that can
// POST to a Ministry-controlled or Ministry-logged origin.
//
// - Preferred path: navigator.credentials.store() — no form at all.
// - Fallback (no PasswordCredential: Safari, Firefox): a save form that is
//   network-incapable BY CONSTRUCTION — method="dialog" inside a <dialog>, no
//   action, no named fields — with preventDefault bound to the form's SUBMIT
//   event (not a click handler), so Enter in the password field also produces
//   zero requests. A JS-less submit just closes the dialog.
// - The vendor-cloud disclosure (I8) renders ABOVE the save action, always,
//   before the user can save.

export function PmSave({ userId }: { userId: string }) {
  const [state, setState] = useState<"idle" | "stored" | "fallback" | "manual" | "failed">("idle");
  const dialogRef = useRef<HTMLDialogElement>(null);
  // The canonical string enters this component only for the fallback dialog —
  // one of the two permitted string surfaces (spec §12 check 14).
  const [fallbackSecret, setFallbackSecret] = useState<string | null>(null);

  async function save() {
    if (passwordCredentialSupported()) {
      const result = await savePasswordToManager(userId);
      if (result === "stored") {
        setState("stored");
        return;
      }
      if (result === "failed") {
        setState("failed");
        return;
      }
    }
    // Fallback: the network-incapable dialog form.
    const secret = getSeedBackupString(userId);
    if (secret === null) {
      setState("failed");
      return;
    }
    setFallbackSecret(secret);
    setState("fallback");
    // Open on next tick so the inputs exist when the dialog shows.
    requestAnimationFrame(() => dialogRef.current?.showModal());
  }

  return (
    <div className="rounded-md border border-neutral-200 p-3 dark:border-neutral-800">
      <div className="text-sm font-medium">Save in your password manager</div>
      <p className="mt-1 rounded-md border border-amber-200 bg-amber-50 p-2 text-sm text-amber-900 dark:border-amber-900/40 dark:bg-amber-950/30 dark:text-amber-200">
        Your key is stored by your browser&apos;s password manager. If it syncs (iCloud Keychain,
        Google Password Manager, a third-party manager), a copy of your key lives in that
        vendor&apos;s cloud and is reachable by anyone who can recover that account. Ministry never
        has your key.
      </p>
      <div className="mt-2">
        {state === "stored" ? (
          <p className="text-sm font-medium text-green-700 dark:text-green-400">
            Saved to your password manager.
          </p>
        ) : state === "manual" ? (
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            If it didn&apos;t offer to save, add an entry manually: this site, username{" "}
            <code className="font-mono">{PM_CREDENTIAL_ID}</code>, password = your key string from
            the backup.
          </p>
        ) : (
          <Button type="button" variant="outline" onClick={save}>
            Save my key
          </Button>
        )}
        {state === "failed" ? (
          <p className="mt-2 text-sm text-amber-700 dark:text-amber-400">
            Couldn&apos;t save automatically. Add it to your password manager manually from your
            backup file.
          </p>
        ) : null}
      </div>

      {fallbackSecret !== null ? (
        <dialog
          ref={dialogRef}
          className="rounded-lg border border-neutral-200 p-4 shadow-lg backdrop:bg-black/40 dark:border-neutral-800 dark:bg-neutral-950 dark:text-neutral-100"
        >
          {/* Network-incapable by construction (I11): method="dialog", no
              action, no named fields — submitting can only close the dialog,
              never issue a request. preventDefault is on the SUBMIT event so
              Enter in the field is intercepted where it actually fires. */}
          <form
            method="dialog"
            onSubmit={(e) => {
              e.preventDefault();
              dialogRef.current?.close();
              setFallbackSecret(null);
              setState("manual");
            }}
          >
            <h4 className="text-sm font-semibold">Save your key</h4>
            <p className="mt-1 max-w-sm text-sm text-neutral-600 dark:text-neutral-400">
              Press save and your browser should offer to remember this as a login for Ministry.
            </p>
            <div className="mt-3 flex flex-col gap-2">
              <input
                type="text"
                autoComplete="username"
                defaultValue={PM_CREDENTIAL_ID}
                readOnly
                aria-label="Key entry username"
                className="rounded-md border border-neutral-300 bg-neutral-50 px-3 py-2 font-mono text-sm dark:border-neutral-700 dark:bg-neutral-900"
              />
              <input
                type="password"
                autoComplete="new-password"
                defaultValue={fallbackSecret}
                readOnly
                aria-label="Private Identity"
                className="rounded-md border border-neutral-300 bg-neutral-50 px-3 py-2 font-mono text-sm dark:border-neutral-700 dark:bg-neutral-900"
              />
            </div>
            <div className="mt-3 flex justify-end gap-2">
              <Button type="submit">Save</Button>
            </div>
          </form>
        </dialog>
      ) : null}
    </div>
  );
}
