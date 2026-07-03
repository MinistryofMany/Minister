import { Eye, EyeOff, GripVertical, type LucideIcon } from "lucide-react";
import {
  AtSign,
  Cake,
  Globe,
  Link as LinkIcon,
  Mail,
  MapPin,
  ShieldCheck,
  Ticket,
  Users,
} from "lucide-react";

import type { BadgeIconKey } from "@minister/shared";

import type { DisplayBadge } from "@/lib/badges";
import { summarizeAttributes } from "@/lib/badges";
import { cn } from "@/lib/utils";

// `satisfies Record<BadgeIconKey, ...>` makes the registry's icon keys
// the source of truth: a new badge type whose iconKey isn't mapped here
// fails the typecheck instead of degrading to the runtime fallback. The
// `Record<string, ...>` annotation keeps the lookup indexable by the
// view type's `iconKey: string` while the `satisfies` still enforces
// exhaustiveness over BadgeIconKey.
const ICONS: Record<string, LucideIcon> = {
  "at-sign": AtSign,
  cake: Cake,
  globe: Globe,
  link: LinkIcon,
  mail: Mail,
  "map-pin": MapPin,
  "shield-check": ShieldCheck,
  ticket: Ticket,
  users: Users,
} satisfies Record<BadgeIconKey, LucideIcon>;

interface BadgeCardProps {
  badge: DisplayBadge;
  // When true, render reorder handle + visibility controls. False for
  // the public profile view.
  editable: boolean;
  // Slot for caller-provided action buttons (toggle, delete).
  action?: React.ReactNode;
  // Drag-attaching helpers from useSortable. Caller wires these to the
  // reorder handle so individual buttons stay clickable.
  dragHandleProps?: React.HTMLAttributes<HTMLButtonElement>;
}

export function BadgeCard({ badge, editable, action, dragHandleProps }: BadgeCardProps) {
  const Icon = ICONS[badge.meta.iconKey] ?? ShieldCheck;
  const summary = summarizeAttributes(badge.type, badge.attributes);

  return (
    <div
      className={cn(
        "group relative flex items-center gap-3 rounded-lg border border-neutral-200 bg-white p-4 shadow-sm transition-shadow hover:shadow-md dark:border-neutral-800 dark:bg-neutral-950",
        !badge.isPublic && editable && "border-dashed",
      )}
    >
      {editable ? (
        <button
          type="button"
          aria-label="Drag to reorder"
          className="cursor-grab touch-none rounded p-1 text-neutral-400 hover:bg-neutral-100 active:cursor-grabbing dark:hover:bg-neutral-900"
          {...dragHandleProps}
        >
          <GripVertical className="h-4 w-4" />
        </button>
      ) : null}

      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-neutral-100 text-neutral-700 dark:bg-neutral-900 dark:text-neutral-300">
        <Icon className="h-5 w-5" />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <h3 className="truncate text-sm font-medium">{badge.meta.label}</h3>
          {editable ? (
            <span
              className={cn(
                "inline-flex items-center gap-1 rounded-full px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide",
                badge.isPublic
                  ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400"
                  : "bg-neutral-100 text-neutral-500 dark:bg-neutral-900 dark:text-neutral-400",
              )}
              title={badge.isPublic ? "Visible on public profile" : "Private"}
            >
              {badge.isPublic ? <Eye className="h-3 w-3" /> : <EyeOff className="h-3 w-3" />}
              {badge.isPublic ? "Public" : "Private"}
            </span>
          ) : null}
        </div>
        {summary ? (
          <p className="truncate text-sm text-neutral-600 dark:text-neutral-400">{summary}</p>
        ) : null}
      </div>

      {action ? <div className="flex items-center gap-1">{action}</div> : null}
    </div>
  );
}
