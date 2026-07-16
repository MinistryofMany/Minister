"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  pollForRoot,
  renderQrImageUrl,
  startDisplaySession,
  type DisplaySession,
} from "@/lib/anon-seed/pair-client";
import { unlockWithSeedInput } from "@/lib/anon-seed/vault";

// The display device's state machine. The private key of the pairing key pair
// lives only in `session.keyPair` (never serialized, never uploaded); the QR
// carries only the public half. When the 3-minute session lapses the page
// silently mints a fresh one, up to MAX_CYCLES, then stops.

const MAX_CYCLES = 3;
const POLL_MS = 1500;

type Phase = "starting" | "displaying" | "received" | "exhausted" | "error";

export function GetKeyClient({ userId, epoch }: { userId: string; epoch: number }) {
  const [phase, setPhase] = useState<Phase>("starting");
  const [qrUrl, setQrUrl] = useState<string | null>(null);
  const [code, setCode] = useState<string | null>(null);
  const [qrText, setQrText] = useState<string | null>(null);
  const [remaining, setRemaining] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [cycle, setCycle] = useState(0);

  const sessionRef = useRef<DisplaySession | null>(null);
  const inflight = useRef(false);

  // Mint (or re-mint) a session whenever we enter the "starting" phase.
  useEffect(() => {
    if (phase !== "starting") return;
    let cancelled = false;
    setQrUrl(null);
    (async () => {
      try {
        const session = await startDisplaySession();
        const rendered = await renderQrImageUrl(session.qrText);
        if (cancelled) return;
        sessionRef.current = session;
        setQrUrl(rendered);
        setCode(session.code);
        setQrText(session.qrText);
        setRemaining(Math.max(0, session.expiresAt - Date.now()));
        setPhase("displaying");
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : "Could not start pairing.");
        setPhase("error");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [phase, cycle]);

  // Poll for the sealed payload and run the countdown while displaying.
  useEffect(() => {
    if (phase !== "displaying") return;
    const timer = setInterval(() => {
      const session = sessionRef.current;
      if (!session) return;
      const left = session.expiresAt - Date.now();
      setRemaining(Math.max(0, left));
      if (left <= 0) {
        // Session lapsed: re-mint a fresh one, or give up after MAX_CYCLES.
        if (cycle + 1 < MAX_CYCLES) {
          setCycle((c) => c + 1);
          setPhase("starting");
        } else {
          setPhase("exhausted");
        }
        return;
      }
      if (inflight.current) return;
      inflight.current = true;
      void pollForRoot(session, userId, epoch)
        .then((res) => {
          if (res.status === "received") setPhase("received");
          else if (res.status === "expired") setRemaining(0);
          else if (res.status === "error") {
            setError(res.message);
            setPhase("error");
          }
        })
        .finally(() => {
          inflight.current = false;
        });
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [phase, cycle, userId, epoch]);

  if (phase === "received") return <ReceivedCard />;

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Scan this with your other device</CardTitle>
          <CardDescription>
            {phase === "exhausted"
              ? "This code expired."
              : phase === "error"
                ? "Something went wrong."
                : "On the device that has your key: Settings → Private Identity → Add a device, then point its camera here."}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col items-center gap-4">
          {phase === "error" ? (
            <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
          ) : phase === "exhausted" ? (
            <Button
              type="button"
              onClick={() => {
                setCycle(0);
                setError(null);
                setPhase("starting");
              }}
            >
              Show a new code
            </Button>
          ) : qrUrl ? (
            <>
              {/* PNG data URL from zxing-wasm — no raw HTML injected. */}
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={qrUrl}
                alt="Pairing QR code"
                width={224}
                height={224}
                className="rounded-lg bg-white p-3"
              />
              {code ? (
                <p className="text-center text-sm text-neutral-600 dark:text-neutral-400">
                  If asked, type this code on your other device:{" "}
                  <span className="font-mono text-base font-semibold tracking-widest">{code}</span>
                </p>
              ) : null}
              {qrText ? (
                <p className="break-all text-center font-mono text-xs text-neutral-500 dark:text-neutral-500">
                  {qrText}
                </p>
              ) : null}
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Expires in {Math.ceil(remaining / 1000)}s. Waiting for the other device…
              </p>
            </>
          ) : (
            <p className="text-sm text-neutral-600 dark:text-neutral-400">Preparing a code…</p>
          )}
        </CardContent>
      </Card>

      <ManualEntryCard userId={userId} epoch={epoch} onReceived={() => setPhase("received")} />
    </>
  );
}

// Manual-entry fallback, offered with equal weight (identity plan): type the
// 28-character backup string instead of scanning. Same destination — the vault
// unlocks and persists the root on this device.
function ManualEntryCard({
  userId,
  epoch,
  onReceived,
}: {
  userId: string;
  epoch: number;
  onReceived: () => void;
}) {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setError(null);
    setBusy(true);
    try {
      await unlockWithSeedInput(userId, value, epoch);
      setValue("");
      onReceived();
    } catch {
      setError("That doesn't look like a valid backup string. Check it and try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Or enter your backup string</CardTitle>
        <CardDescription>
          No camera handy? Type the 28-character backup string you saved when you created your
          Private Identity.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {error ? <p className="text-sm text-red-700 dark:text-red-400">{error}</p> : null}
        <textarea
          value={value}
          onChange={(e) => setValue(e.target.value)}
          autoComplete="off"
          spellCheck={false}
          rows={2}
          className="w-full rounded-md border border-neutral-300 bg-transparent p-2 font-mono text-sm dark:border-neutral-700"
          placeholder="your 28-character backup string"
        />
        <Button
          type="button"
          variant="outline"
          className="self-start"
          disabled={busy || value.trim().length === 0}
          onClick={submit}
        >
          {busy ? "Checking…" : "Use my backup string"}
        </Button>
      </CardContent>
    </Card>
  );
}

function ReceivedCard() {
  return (
    <Card className="border-green-200 dark:border-green-900/40">
      <CardHeader>
        <CardTitle>Key received</CardTitle>
        <CardDescription>
          Your Private Identity is now on this device. You&apos;re all set.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Button asChild variant="outline">
          <Link href="/settings/private-identity">Done</Link>
        </Button>
      </CardContent>
    </Card>
  );
}
