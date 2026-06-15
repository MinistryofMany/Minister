// Plugin interface for Minister badge plugins. Mirrors the shape sketched
// in CLAUDE.md. Plugins live in-process under
// `apps/minister/src/plugins/<id>/` and are registered via a central
// registry — no dynamic loading.

export type WizardStepKind = "form" | "redirect" | "extension-action" | "magic-link" | "info";

// ---------------------------------------------------------------------------
// Per-kind payload shapes. The wizard UI dispatches to a built-in
// renderer for each kind, so most plugins write zero React.
// ---------------------------------------------------------------------------

export interface FormFieldDef {
  name: string;
  label: string;
  type: "text" | "email" | "select" | "number";
  placeholder?: string;
  helpText?: string;
  required?: boolean;
  options?: Array<{ value: string; label: string }>;
}

export interface FormStepPayload {
  title: string;
  description?: string;
  fields: FormFieldDef[];
  submitLabel?: string;
}

export interface RedirectStepPayload {
  url: string;
  description?: string;
  // Random opaque value the plugin issues alongside the redirect.
  // Stored as WizardSession.pendingToken so the callback route can
  // resolve the session by ?state=<token>. Required for OAuth / SAML
  // round trips; can be omitted if the plugin doesn't need to
  // correlate the callback to a specific in-flight wizard.
  expectedState?: string;
}

export interface ExtensionActionStepPayload {
  // What the extension should do (e.g. TLSNotary a specific endpoint).
  // Shape is plugin-defined; the extension is expected to know how to
  // interpret it.
  action: string;
  params: Record<string, unknown>;
  description?: string;
  // Random opaque value the plugin issues alongside the extension
  // request. Stored as WizardSession.pendingToken so the
  // /api/tlsn/submit endpoint can resolve the right wizard session
  // when the extension POSTs the finalized presentation back. The
  // extension echoes this value verbatim as `sessionToken`.
  expectedSubmissionToken?: string;
}

export interface MagicLinkStepPayload {
  // What recipient the link was sent to, for display.
  sentTo: string;
  description?: string;
  // Echoed back to the plugin from the link click. Treated as opaque by
  // the wizard runtime.
  expectedToken?: string;
}

export interface InfoStepPayload {
  title: string;
  body: string;
  continueLabel?: string;
}

export type StepPayload =
  | FormStepPayload
  | RedirectStepPayload
  | ExtensionActionStepPayload
  | MagicLinkStepPayload
  | InfoStepPayload;

// Discriminated union on `kind`. A `switch (step.kind)` narrows the
// payload type automatically — no casts at the call sites.
export type WizardStep =
  | { id: string; kind: "form"; payload: FormStepPayload }
  | { id: string; kind: "redirect"; payload: RedirectStepPayload }
  | {
      id: string;
      kind: "extension-action";
      payload: ExtensionActionStepPayload;
    }
  | { id: string; kind: "magic-link"; payload: MagicLinkStepPayload }
  | { id: string; kind: "info"; payload: InfoStepPayload };

// ---------------------------------------------------------------------------
// Wizard state + plugin shape
// ---------------------------------------------------------------------------

export interface PluginManifest {
  id: string;
  name: string;
  description: string;
  badgeTypes: string[];
  requiresExtension: boolean;
  iconKey?: string;
}

export interface WizardState {
  pluginId: string;
  userId: string;
  currentStep: WizardStep;
  // Accumulated per-step data. Server-side only — never sent to the
  // client unless the plugin explicitly includes it in payload.
  data: Record<string, unknown>;
}

export interface IssuedBadge {
  type: string;
  // Denormalized display attributes — saved on Badge.attributes for
  // querying/UI. Must not contain anything sensitive; the VC payload is
  // the authoritative artifact.
  attributes: Record<string, unknown>;
  // Claims that will go into the credentialSubject of the VC. Must
  // satisfy the badge type's Zod schema (the issuance runtime validates
  // before signing).
  claims: Record<string, unknown>;
  expiresAt?: Date;
  eligibilities?: Array<{
    badgeType: string;
    eligibleAt: Date;
    fuzzDays: number;
  }>;
}

export interface PluginAuditLogger {
  log(action: string, metadata: Record<string, unknown>): Promise<void>;
}

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

export interface PluginContext {
  userId: string;
  // Origin the user is hitting the app on. Plugins need this to build
  // magic-link callback URLs, OAuth redirect URIs, etc.
  origin: string;
  audit: PluginAuditLogger;
  // Transport for plugin-originated emails (verification links, etc.).
  // Concrete implementation is provided by apps/minister so plugins don't
  // depend on a specific mailer.
  sendMail(message: MailMessage): Promise<void>;
}

export type HandleStepResult =
  | { kind: "continue"; state: WizardState }
  | { kind: "complete"; badges: IssuedBadge[] }
  | { kind: "error"; message: string };

export interface Plugin {
  manifest: PluginManifest;
  startWizard(ctx: PluginContext): Promise<WizardState>;
  handleStep(state: WizardState, input: unknown, ctx: PluginContext): Promise<HandleStepResult>;
}
