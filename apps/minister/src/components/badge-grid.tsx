"use client";

import { useEffect, useState, useTransition } from "react";
import {
  DndContext,
  PointerSensor,
  closestCenter,
  useSensor,
  useSensors,
  type DragEndEvent,
} from "@dnd-kit/core";
import {
  SortableContext,
  arrayMove,
  useSortable,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";

import { BadgeCard } from "@/components/badge-card";
import { BadgeDeleteForm } from "@/components/badge-delete-form";
import { BadgeToggleForm } from "@/components/badge-toggle-form";
import type { DisplayBadge } from "@/lib/badges";
import { reorderBadges } from "@/server/badge-actions";

interface BadgeGridProps {
  badges: DisplayBadge[];
}

export function BadgeGrid({ badges }: BadgeGridProps) {
  const [order, setOrder] = useState(badges);
  const [, startTransition] = useTransition();

  // Sync local state when the server returns a new list (e.g. after
  // delete or new badge issue).
  useEffect(() => {
    setOrder(badges);
  }, [badges]);

  const sensors = useSensors(
    useSensor(PointerSensor, {
      // Require a small movement before starting a drag so the toggle
      // and delete buttons stay tap-able.
      activationConstraint: { distance: 6 },
    }),
  );

  function handleDragEnd(event: DragEndEvent) {
    const { active, over } = event;
    if (!over || active.id === over.id) return;

    const oldIndex = order.findIndex((b) => b.id === active.id);
    const newIndex = order.findIndex((b) => b.id === over.id);
    if (oldIndex < 0 || newIndex < 0) return;

    const next = arrayMove(order, oldIndex, newIndex);
    setOrder(next);
    startTransition(async () => {
      await reorderBadges({ orderedIds: next.map((b) => b.id) });
    });
  }

  if (order.length === 0) return null;

  return (
    <DndContext
      sensors={sensors}
      collisionDetection={closestCenter}
      onDragEnd={handleDragEnd}
    >
      <SortableContext
        items={order.map((b) => b.id)}
        strategy={verticalListSortingStrategy}
      >
        <ul className="flex flex-col gap-3">
          {order.map((badge) => (
            <SortableBadgeRow key={badge.id} badge={badge} />
          ))}
        </ul>
      </SortableContext>
    </DndContext>
  );
}

function SortableBadgeRow({ badge }: { badge: DisplayBadge }) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id: badge.id });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.6 : 1,
  };

  return (
    <li ref={setNodeRef} style={style}>
      <BadgeCard
        badge={badge}
        editable
        dragHandleProps={{ ...attributes, ...listeners }}
        action={
          <>
            <BadgeToggleForm
              badgeId={badge.id}
              isPublic={badge.isPublic}
            />
            <BadgeDeleteForm badgeId={badge.id} />
          </>
        }
      />
    </li>
  );
}
