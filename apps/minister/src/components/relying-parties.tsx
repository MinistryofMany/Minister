// Shared between the logged-out home page (/) and the logged-in profile
// page (/profile) so both surfaces list the same relying-party apps instead
// of only ever showing them to visitors who haven't signed in yet.
export const relyingParties = [
  {
    name: "FreedInk",
    url: "https://freed.ink",
    description:
      "A blog a community writes together. Prove you belong to the group, then write under a pseudonym - ideas stand on their own, and no single author gets singled out.",
  },
  {
    name: "Discreetly",
    url: "https://discreetly.chat",
    description:
      "Chat rooms for communities. Each room asks you to prove something to get in, you show up under a pseudonym, and messages don't stick around forever.",
  },
  {
    name: "Deforum",
    url: "https://deforum.space",
    description:
      "Forums where each space asks for a badge to get in, and you take part under a pseudonym.",
  },
] as const;

export function RelyingParties() {
  return (
    <section className="space-y-3">
      <div className="space-y-1">
        <h2 className="text-lg font-semibold tracking-tight">Sign in with Minister</h2>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Apps that check your badges at the door and know you only by a pseudonym.
        </p>
      </div>
      <ul className="space-y-3">
        {relyingParties.map((app) => (
          <li key={app.url}>
            <a
              href={app.url}
              target="_blank"
              rel="noopener noreferrer"
              className="block rounded-lg border border-neutral-200 bg-white p-4 shadow-sm transition-colors hover:border-neutral-300 hover:bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-950 dark:hover:border-neutral-700 dark:hover:bg-neutral-900"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium text-neutral-900 dark:text-neutral-100">
                  {app.name}
                </span>
                <span aria-hidden className="text-neutral-400 dark:text-neutral-500">
                  ↗
                </span>
              </div>
              <p className="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
                {app.description}
              </p>
            </a>
          </li>
        ))}
      </ul>
    </section>
  );
}
