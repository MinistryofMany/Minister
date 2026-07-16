import { notFound, redirect } from "next/navigation";

import { env } from "@/env";
import { getCurrentSession } from "@/lib/session";

import { AddDeviceClient } from "./add-device-client";

// SCAN side of QR pairing: this device HOLDS the root and sends it to a device
// that needs it. It scans the other device's QR, seals the root to the scanned
// key, and deposits the sealed blob on the blind relay. `userId` is THIS
// device's own authenticated session (C2) — the seal is account-checked
// server-side against it.
export default async function AddDevicePage() {
  if (!env.ANON_IDENTITY_ENABLED) notFound();

  const session = await getCurrentSession();
  if (!session?.user?.id) redirect("/");

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Add a device</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Point your camera at the code shown on the device that needs your Private Identity. Your
          key is sent to it end-to-end encrypted — Ministry never sees it, and this cannot be
          undone.
        </p>
      </header>

      <AddDeviceClient userId={session.user.id} />
    </div>
  );
}
