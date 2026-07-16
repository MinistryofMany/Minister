import { requireSetupComplete } from "@/lib/session";

// Gated section: a signed-in user who hasn't finished the forced /welcome setup
// guide is bounced there before any share-management page renders.
export default async function SharesLayout({ children }: { children: React.ReactNode }) {
  await requireSetupComplete();
  return children;
}
