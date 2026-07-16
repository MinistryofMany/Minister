"use client";

import { useEffect, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  autofillFromPasswordManager,
  getMemoryOnlyPref,
  passwordCredentialSupported,
  unlockWithPasskey,
  unlockWithSeedInput,
} from "@/lib/anon-seed/vault";

// The daily-key unlock (spec §7): L1 passkey tap where a wrapped blob exists,
// then the L2/L0 entry field — ONE input that a password manager fills (L2)
// or the user types into (L0). A vault-OWNED component (I4).
//
// Findings W1 + W2, honored structurally:
// - The field lives OUTSIDE every server-posting form: no form element exists
//   anywhere in this component (the consent screen posts via server actions,
//   not forms, and this panel is never nested in one).
// - The field carries NO name attribute, so no form serialization anywhere in
//   the DOM could ever include it.
// - Its value is read only by vault JS (the unlock handler below), and the
//   field is cleared here on success and by the consent screen via clearRef
//   before any consent submit is dispatched.

export interface UnlockPanelProps {
  userId: string;
  hasPasskeyBlobs: boolean;
  // The consent screen stores a cleaner here and runs it before dispatching
  // approve — the W1 "cleared before submit" guarantee.
  clearRef?: React.MutableRefObject<(() => void) | null>;
  onUnlocked: () => void;
}

export function UnlockPanel({ userId, hasPasskeyBlobs, clearRef, onUnlocked }: UnlockPanelProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [show, setShow] = useState(false);
  // Browser-only capabilities resolve after mount so the SSR'd HTML and the
  // hydration render agree (no hydration mismatch).
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    setMounted(true);
  }, []);
  const memoryOnly = mounted && getMemoryOnlyPref(userId);
  const pmSupported = mounted && passwordCredentialSupported();

  useEffect(() => {
    if (!clearRef) return;
    clearRef.current = () => {
      if (inputRef.current) inputRef.current.value = "";
    };
    return () => {
      clearRef.current = null;
    };
  }, [clearRef]);

  async function passkeyUnlock() {
    setMessage(null);
    setBusy(true);
    const result = await unlockWithPasskey(userId);
    setBusy(false);
    if (result.ok) {
      onUnlocked();
      return;
    }
    setMessage(result.message);
  }

  async function autofill() {
    setMessage(null);
    setBusy(true);
    try {
      const result = await autofillFromPasswordManager(userId);
      if (result === "unlocked") {
        if (inputRef.current) inputRef.current.value = "";
        onUnlocked();
        return;
      }
      if (result === "none") {
        setMessage("No saved Private Identity found — type or paste it below.");
        inputRef.current?.focus();
      }
    } catch {
      setMessage(
        "The saved entry isn't a valid Private Identity. Enter it from your backup instead.",
      );
    } finally {
      setBusy(false);
    }
  }

  function manualUnlock() {
    setMessage(null);
    const value = inputRef.current?.value ?? "";
    if (value.trim().length === 0) {
      setMessage("Enter your 28-character Private Identity or the 12 words.");
      return;
    }
    try {
      unlockWithSeedInput(userId, value);
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "That isn't a valid Private Identity.");
      return;
    }
    if (inputRef.current) inputRef.current.value = "";
    onUnlocked();
  }

  return (
    <div className="space-y-3">
      {message ? (
        <p className="rounded-md border border-amber-200 bg-amber-50 p-2 text-sm text-amber-800 dark:border-amber-900/40 dark:bg-amber-950/30 dark:text-amber-300">
          {message}
        </p>
      ) : null}

      {hasPasskeyBlobs && !memoryOnly ? (
        <Button type="button" onClick={passkeyUnlock} disabled={busy}>
          {busy ? "Working…" : "Unlock with passkey"}
        </Button>
      ) : null}

      <div className="space-y-2">
        <label htmlFor="anon-seed-unlock" className="block text-sm font-medium">
          {hasPasskeyBlobs && !memoryOnly
            ? "Or enter your Private Identity"
            : "Enter your Private Identity"}
        </label>
        {memoryOnly ? (
          <p className="text-xs text-neutral-500 dark:text-neutral-400">
            You&apos;ve chosen never to store your Private Identity, so it&apos;s needed once per
            session.
          </p>
        ) : null}
        {/* W1: no name attribute, outside any form, read only by vault JS. */}
        <input
          id="anon-seed-unlock"
          ref={inputRef}
          type={show ? "text" : "password"}
          autoComplete="current-password"
          spellCheck={false}
          autoCapitalize="none"
          placeholder="28-character Private Identity or 12 words"
          data-anon-seed-input="true"
          className="flex h-10 w-full rounded-md border border-neutral-300 bg-white px-3 py-2 font-mono text-sm placeholder:font-sans placeholder:text-neutral-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-400 dark:border-neutral-700 dark:bg-neutral-950 dark:placeholder:text-neutral-500"
        />
        <label className="flex items-center gap-2 text-xs text-neutral-500 dark:text-neutral-400">
          <input
            type="checkbox"
            className="h-3.5 w-3.5"
            checked={show}
            onChange={(e) => setShow(e.target.checked)}
          />
          Show what I&apos;m typing
        </label>
        <div className="flex gap-2">
          {!memoryOnly && pmSupported ? (
            <Button type="button" variant="outline" onClick={autofill} disabled={busy}>
              Use saved Private Identity
            </Button>
          ) : null}
          <Button type="button" variant="outline" onClick={manualUnlock} disabled={busy}>
            Unlock
          </Button>
        </div>
      </div>
    </div>
  );
}
