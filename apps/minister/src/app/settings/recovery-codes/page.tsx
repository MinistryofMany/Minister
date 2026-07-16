import { redirect } from "next/navigation";

// Recovery codes were folded into the consolidated Account recovery section
// (docs/identity-secrets-problem.md, O-3). This route is kept as a permanent
// redirect so existing links/bookmarks still land in the right place.
export default function RecoveryCodesPage() {
  redirect("/settings/security");
}
