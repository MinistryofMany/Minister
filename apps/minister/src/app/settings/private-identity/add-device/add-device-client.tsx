"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  fetchPeerFacts,
  parseScannedQr,
  scanQrFromImage,
  sealToPeer,
  type PeerFacts,
  type ScannedQr,
} from "@/lib/anon-seed/pair-client";
import { unlockFromStore } from "@/lib/anon-seed/vault";

// The root-holder's state machine. It first loads its own root from on-device
// storage (only a device that HAS the root can be the source), then scans, then
// runs the confirm gate. S1: the pairing code is rendered ONLY as a typing
// forcing function ("type the code shown on the other device"), never as a
// "do these match?" check — a phished victim would compute the attacker's code
// and it would match. When the peer is in a different country (or its country is
// unknown), typing is REQUIRED.

type Phase = "loading" | "no-key" | "scanning" | "camera-denied" | "confirm" | "sealing" | "done";

const SCAN_INTERVAL_MS = 400;

export function AddDeviceClient({ userId }: { userId: string }) {
  const [phase, setPhase] = useState<Phase>("loading");
  const [scanned, setScanned] = useState<ScannedQr | null>(null);
  const [facts, setFacts] = useState<PeerFacts | null>(null);
  const [error, setError] = useState<string | null>(null);

  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);

  // Load this device's own root. If none is stored, this device cannot be the
  // source of a pairing.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const ok = await unlockFromStore(userId).catch(() => false);
      if (cancelled) return;
      setPhase(ok ? "scanning" : "no-key");
    })();
    return () => {
      cancelled = true;
    };
  }, [userId]);

  const stopCamera = useCallback(() => {
    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
  }, []);

  // When a QR parses, stop the camera and move to the confirm gate, pulling the
  // peer's connection facts to decide whether the typed code is required.
  const onDetected = useCallback(
    async (qr: ScannedQr) => {
      stopCamera();
      setScanned(qr);
      setFacts(await fetchPeerFacts(qr.sessionId));
      setPhase("confirm");
    },
    [stopCamera],
  );

  // Camera capture loop while scanning.
  useEffect(() => {
    if (phase !== "scanning") return;
    let cancelled = false;
    let timer: ReturnType<typeof setInterval> | null = null;
    const canvas = document.createElement("canvas");

    (async () => {
      let stream: MediaStream;
      try {
        stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: "environment" },
        });
      } catch {
        if (!cancelled) setPhase("camera-denied");
        return;
      }
      if (cancelled) {
        stream.getTracks().forEach((t) => t.stop());
        return;
      }
      streamRef.current = stream;
      const video = videoRef.current;
      if (!video) return;
      video.srcObject = stream;
      await video.play().catch(() => undefined);

      timer = setInterval(async () => {
        if (cancelled || !video.videoWidth) return;
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        const ctx = canvas.getContext("2d");
        if (!ctx) return;
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const text = await scanQrFromImage(image).catch(() => null);
        if (!text || cancelled) return;
        const qr = parseScannedQr(text);
        if (!qr) return; // a foreign QR / URL — ignore and keep scanning.
        if (timer) clearInterval(timer);
        void onDetected(qr);
      }, SCAN_INTERVAL_MS);
    })();

    return () => {
      cancelled = true;
      if (timer) clearInterval(timer);
      stopCamera();
    };
  }, [phase, onDetected, stopCamera]);

  useEffect(() => stopCamera, [stopCamera]);

  if (phase === "loading") {
    return <InfoCard title="Checking this device…" body="One moment." />;
  }
  if (phase === "no-key") {
    return (
      <InfoCard
        title="This device doesn't have your key yet"
        body="Only a device that already holds your Private Identity can send it to another. Unlock it here first, or use the other device as the sender."
        action={{ href: "/settings/private-identity", label: "Back to Private Identity" }}
      />
    );
  }
  if (phase === "done") {
    return (
      <InfoCard
        title="Device added"
        body="Your Private Identity was sent to the other device, end-to-end encrypted."
        action={{ href: "/settings/private-identity", label: "Done" }}
      />
    );
  }

  if (phase === "confirm" && scanned) {
    return (
      <ConfirmCard
        userId={userId}
        scanned={scanned}
        facts={facts}
        onDone={() => setPhase("done")}
        onRescan={() => {
          setScanned(null);
          setFacts(null);
          setError(null);
          setPhase("scanning");
        }}
      />
    );
  }

  // scanning or camera-denied
  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>
            {phase === "camera-denied" ? "Camera unavailable" : "Point at the code"}
          </CardTitle>
          <CardDescription>
            {phase === "camera-denied"
              ? "No camera access. Paste the code text from the other device instead."
              : "Line up the QR code shown on the device that needs your key."}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col items-center gap-3">
          {phase === "scanning" ? (
            <video
              ref={videoRef}
              muted
              playsInline
              className="aspect-square w-full max-w-sm rounded-lg bg-black object-cover"
            />
          ) : null}
          {error ? <p className="text-sm text-red-700 dark:text-red-400">{error}</p> : null}
        </CardContent>
      </Card>

      <ManualPasteCard
        onParsed={(qr) => {
          stopCamera();
          void onDetected(qr);
        }}
        onError={setError}
      />
    </>
  );
}

function ConfirmCard({
  userId,
  scanned,
  facts,
  onDone,
  onRescan,
}: {
  userId: string;
  scanned: ScannedQr;
  facts: PeerFacts | null;
  onDone: () => void;
  onRescan: () => void;
}) {
  const [typedCode, setTypedCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attack, setAttack] = useState(false);

  // Require the typed code when the peer is in a different country, or its
  // country is unknown (fail-safe). Facts unavailable → also require it.
  const requireCode = !facts || !facts.sameCountryAsYou;
  const codeOk = typedCode.trim().toUpperCase() === scanned.code;

  async function confirm() {
    setError(null);
    setAttack(false);
    setBusy(true);
    const result = await sealToPeer({
      userId,
      sessionId: scanned.sessionId,
      publicKey: scanned.publicKey,
    });
    setBusy(false);
    if (result.ok) {
      onDone();
      return;
    }
    setError(result.message);
    if (result.reason === "cross_account") setAttack(true);
  }

  return (
    <Card className="border-amber-200 dark:border-amber-900/40">
      <CardHeader>
        <CardTitle>Send your key to this device?</CardTitle>
        <CardDescription>{describeFacts(facts)}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div
          className={
            attack
              ? "rounded-md border border-red-300 bg-red-50 p-3 text-sm text-red-800 dark:border-red-900/50 dark:bg-red-950/40 dark:text-red-300"
              : "rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-900/50 dark:bg-amber-950/30 dark:text-amber-200"
          }
        >
          {error ??
            "This gives that device your Private Identity, permanently. There is no undo. Only continue if that screen is physically in front of you right now."}
        </div>

        {requireCode ? (
          <div className="flex flex-col gap-2">
            <label htmlFor="pair-code" className="text-sm">
              Type the 4 characters shown on that device&apos;s screen to continue.
            </label>
            <Input
              id="pair-code"
              value={typedCode}
              onChange={(e) => setTypedCode(e.target.value)}
              autoComplete="off"
              autoCapitalize="characters"
              maxLength={4}
              className="w-32 font-mono uppercase tracking-widest"
              placeholder="••••"
            />
          </div>
        ) : null}

        <div className="flex gap-2">
          <Button
            type="button"
            variant="destructive"
            disabled={busy || (requireCode && !codeOk)}
            onClick={confirm}
          >
            {busy ? "Sending…" : "Send my key"}
          </Button>
          <Button type="button" variant="outline" disabled={busy} onClick={onRescan}>
            Scan again
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function describeFacts(facts: PeerFacts | null): string {
  if (!facts) {
    return "We couldn't read where that device is connecting from. Only continue if it's right in front of you.";
  }
  const where = facts.city ?? facts.country ?? "an unknown location";
  const net = facts.sameNetworkAsYou
    ? "on the same network as this device"
    : "on a different network";
  const country = facts.sameCountryAsYou
    ? ""
    : " That is a different country from you — take extra care.";
  return `That device is connecting from ${where}, ${net}.${country}`;
}

function ManualPasteCard({
  onParsed,
  onError,
}: {
  onParsed: (qr: ScannedQr) => void;
  onError: (msg: string) => void;
}) {
  const [value, setValue] = useState("");

  function submit() {
    const qr = parseScannedQr(value.trim());
    if (!qr) {
      onError("That isn't a Ministry pairing code. Copy the code text from the other device.");
      return;
    }
    onError("");
    onParsed(qr);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Or paste the code text</CardTitle>
        <CardDescription>
          If the other device is this same phone (a second browser) or you can&apos;t use the
          camera, copy the code text shown under its QR and paste it here.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <textarea
          value={value}
          onChange={(e) => setValue(e.target.value)}
          autoComplete="off"
          spellCheck={false}
          rows={2}
          className="w-full rounded-md border border-neutral-300 bg-transparent p-2 font-mono text-sm dark:border-neutral-700"
          placeholder="MP1.…"
        />
        <Button
          type="button"
          variant="outline"
          className="self-start"
          disabled={value.trim().length === 0}
          onClick={submit}
        >
          Use pasted code
        </Button>
      </CardContent>
    </Card>
  );
}

function InfoCard({
  title,
  body,
  action,
}: {
  title: string;
  body: string;
  action?: { href: string; label: string };
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{body}</CardDescription>
      </CardHeader>
      {action ? (
        <CardContent>
          <Button asChild variant="outline">
            <Link href={action.href}>{action.label}</Link>
          </Button>
        </CardContent>
      ) : null}
    </Card>
  );
}
