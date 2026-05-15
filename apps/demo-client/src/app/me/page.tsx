import { redirect } from "next/navigation";

import { auth } from "@/auth";
import { findVerifiedBadge } from "@/lib/vc";

export default async function MePage() {
  const session = await auth();
  if (!session?.user) redirect("/");

  const idTokenClaims = decodeJwtPayload(session.idToken);
  const accessTokenClaims = decodeJwtPayload(session.accessToken);

  // Decode each disclosed VC for display (no verification needed at
  // this stage — the verified inspection is in the next section).
  const decodedVcs = (session.tesseraBadges ?? []).map((jwt) => ({
    jwt,
    decoded: decodeJwtPayload(jwt),
  }));

  // Properly verify one of the VCs against Tessera's JWKS so we can
  // show the RP "did the signature check pass?" affordance.
  const verifiedEmail = await findVerifiedBadge(
    session.tesseraBadges ?? [],
    "email-domain",
  );

  return (
    <main className="mx-auto flex max-w-3xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">
          What the RP got back
        </h1>
        <p className="text-sm text-neutral-600">
          This is everything Tessera gave us during the OIDC handshake. In a
          real RP you&apos;d probably never show users their own tokens —
          rendered here to make the protocol legible.
        </p>
      </header>

      <Block title="Session (RP-side)">
        <Json value={{
          sub: session.tesseraSub,
          name: session.tesseraName,
          picture: session.tesseraPicture,
          badgeCount: session.tesseraBadges?.length ?? 0,
        }} />
      </Block>

      <Block title="id_token (verified by Auth.js)">
        <Json value={idTokenClaims} />
      </Block>

      <Block title="access_token (privacy-clean — no raw userId)">
        <Json value={accessTokenClaims} />
      </Block>

      <Block title="Verified email-domain VC">
        {verifiedEmail ? (
          <Json
            value={{
              iss: verifiedEmail.iss,
              sub: verifiedEmail.sub,
              jti: verifiedEmail.jti,
              type: verifiedEmail.vc.type,
              credentialSubject: verifiedEmail.vc.credentialSubject,
            }}
          />
        ) : (
          <p className="text-sm text-neutral-600">
            None disclosed. The user chose not to share an{" "}
            <code>email-domain</code> badge.
          </p>
        )}
      </Block>

      {decodedVcs.length > 0 ? (
        <Block title={`All disclosed VCs (${decodedVcs.length}, unverified decode)`}>
          {decodedVcs.map((d, i) => (
            <div key={i} className="mb-3">
              <p className="mb-1 text-xs text-neutral-500">VC #{i + 1}</p>
              <Json value={d.decoded} />
            </div>
          ))}
        </Block>
      ) : null}
    </main>
  );
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-neutral-200 bg-white p-4">
      <h2 className="mb-2 text-sm font-semibold">{title}</h2>
      {children}
    </section>
  );
}

function Json({ value }: { value: unknown }) {
  return (
    <pre className="overflow-auto rounded bg-neutral-50 p-3 text-xs">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

// Best-effort base64url JWT payload decode. NOT verification — only
// the verified email-domain section above gives a real proof. This
// just shows the bytes for inspection.
function decodeJwtPayload(jwt: string | null | undefined): unknown {
  if (!jwt) return null;
  const parts = jwt.split(".");
  if (parts.length < 2) return null;
  try {
    const payload = parts[1];
    if (!payload) return null;
    const padded = payload + "=".repeat((4 - (payload.length % 4)) % 4);
    const buf = Buffer.from(padded, "base64");
    return JSON.parse(buf.toString("utf8"));
  } catch {
    return { _error: "could not decode" };
  }
}
