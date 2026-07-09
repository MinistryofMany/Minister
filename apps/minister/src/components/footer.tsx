export function Footer() {
  const buildDate = process.env.NEXT_PUBLIC_BUILD_DATE ?? "dev";
  return (
    <footer className="border-t border-neutral-200 bg-white/60 dark:border-neutral-800 dark:bg-neutral-950/60">
      <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-2 px-4 py-6 text-xs text-neutral-500 dark:text-neutral-400">
        <p>Minister — prototype, not for production use.</p>
        <p className="text-neutral-400 dark:text-neutral-600">Beta · {buildDate}</p>
      </div>
    </footer>
  );
}
