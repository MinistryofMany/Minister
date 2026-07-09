// Plain (non-"use server") module: a "use server" file may only export async
// functions, so runtime value exports like this error class live here and are
// imported by the server actions in credential-actions.ts.

// Raised when addEmail hits the global-unique collision: the address already
// belongs to some account. addEmailAction turns this into a tagged result the
// UI branches on to offer an account merge (the user must still prove control
// of the address, and the merge keeps its own dual-control gate). Carries the
// normalized email so the merge offer can prefill it.
export class EmailCollisionError extends Error {
  readonly email: string;
  constructor(email: string) {
    super("That email is already in use on another account.");
    this.name = "EmailCollisionError";
    this.email = email;
  }
}
