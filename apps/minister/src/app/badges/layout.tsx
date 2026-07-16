import { requireSetupComplete } from "@/lib/session";

// Gated section: a signed-in user who hasn't finished the forced /welcome setup
// guide is bounced there before any badge page renders.
export default async function BadgesLayout({ children }: { children: React.ReactNode }) {
  await requireSetupComplete();
  return children;
}
