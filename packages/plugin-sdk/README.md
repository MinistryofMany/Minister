# @minister/plugin-sdk

Type-only plugin interface contract for Minister badge plugins. Defines the `Plugin` interface, wizard step shapes (form, redirect, extension-action, magic-link, info), the `HandleStepResult` discriminated union, and all supporting types. Plugins implement this contract and are registered in the Minister server's central registry - no dynamic loading.

Part of the **Ministry of Many** project.

## Install

```
pnpm add @minister/plugin-sdk
```

## Usage

```ts
import type {
  Plugin,
  PluginManifest,
  PluginContext,
  WizardState,
  HandleStepResult,
  IssuedBadge,
} from "@minister/plugin-sdk";

export const myPlugin: Plugin = {
  manifest: {
    id: "my-plugin",
    name: "My Plugin",
    description: "Verifies something and issues a badge.",
    badgeTypes: ["email-domain"],
    requiresExtension: false,
    // iconKey: "mail",  // optional
  } satisfies PluginManifest,

  async startWizard(ctx: PluginContext): Promise<WizardState> {
    return {
      pluginId: "my-plugin",
      userId: ctx.userId,
      currentStep: {
        id: "collect-email",
        kind: "form",
        payload: {
          title: "Enter your email",
          fields: [
            {
              name: "email",
              label: "Email address",
              type: "email",
              required: true,
            },
          ],
          submitLabel: "Continue",
        },
      },
      data: {},
    };
  },

  async handleStep(
    state: WizardState,
    input: unknown,
    ctx: PluginContext,
  ): Promise<HandleStepResult> {
    const { currentStep } = state;

    if (currentStep.id === "collect-email") {
      const { email } = input as { email: string };
      // ... send verification email via ctx.sendMail, build magic-link step, etc.
      return {
        kind: "continue",
        state: {
          ...state,
          currentStep: {
            id: "await-link",
            kind: "magic-link",
            payload: { sentTo: email, description: "Click the link to verify." },
          },
          data: { ...state.data, email },
        },
      };
    }

    if (currentStep.id === "await-link") {
      const badge: IssuedBadge = {
        type: "email-domain",
        attributes: { domain: "acme.org" },
        claims: { domain: "acme.org" },
        // expiresAt: new Date("2027-01-01"),
      };
      return { kind: "complete", badges: [badge] };
    }

    return { kind: "error", message: `Unhandled step: ${currentStep.id}` };
  },
};
```

`handleStep` always returns one of three shapes:

- `{ kind: "continue"; state: WizardState }` - advance to the next step
- `{ kind: "complete"; badges: IssuedBadge[] }` - wizard done; runtime validates claims against the badge type schema and issues VCs
- `{ kind: "error"; message: string }` - surface an error to the user

## API

### Core interface

| Export | Purpose |
| ------------------ | --------------------------------------------------------------------------------------------------- | -------- | ------- |
| `Plugin` | The interface every plugin must implement: `manifest`, `startWizard`, `handleStep`. |
| `PluginManifest` | Static plugin metadata: `id`, `name`, `description`, `badgeTypes`, `requiresExtension`, `iconKey?`. |
| `PluginContext` | Runtime context injected by the server: `userId`, `origin`, `audit`, `sendMail`. |
| `HandleStepResult` | Discriminated union returned by `handleStep`: `continue                                             | complete | error`. |

### Wizard step types

| Export                       | `kind`               | Key payload fields                                                               |
| ---------------------------- | -------------------- | -------------------------------------------------------------------------------- |
| `WizardStep`                 | (union)              | Discriminated on `kind`; `switch (step.kind)` narrows the payload automatically. |
| `FormStepPayload`            | `"form"`             | `title`, `fields: FormFieldDef[]`, `submitLabel?`                                |
| `RedirectStepPayload`        | `"redirect"`         | `url`, `expectedState?` (for OAuth/SAML round-trips)                             |
| `ExtensionActionStepPayload` | `"extension-action"` | `action`, `params`, `expectedSubmissionToken?`                                   |
| `MagicLinkStepPayload`       | `"magic-link"`       | `sentTo`, `expectedToken?`                                                       |
| `InfoStepPayload`            | `"info"`             | `title`, `body`, `continueLabel?`                                                |

### Supporting types

| Export              | Purpose                                                                                                           |
| ------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `WizardState`       | Current wizard state: `pluginId`, `userId`, `currentStep`, `data`.                                                |
| `FormFieldDef`      | A single form field: `name`, `label`, `type`, `placeholder?`, `required?`, `options?`.                            |
| `IssuedBadge`       | Badge descriptor returned in a `complete` result: `type`, `attributes`, `claims`, `expiresAt?`, `eligibilities?`. |
| `PluginAuditLogger` | Interface for `ctx.audit.log(action, metadata)`.                                                                  |
| `MailMessage`       | Shape passed to `ctx.sendMail`: `to`, `subject`, `text`, `html?`.                                                 |
| `WizardStepKind`    | `"form" \| "redirect" \| "extension-action" \| "magic-link" \| "info"`                                            |
| `StepPayload`       | Union of all payload types.                                                                                       |

## License

Copyright (c) 2026 AtHeartEngineering LLC, authored by AtHeartEngineer.

Licensed under either of **MIT** ([LICENSE-MIT](./LICENSE-MIT)) or **Apache License 2.0** ([LICENSE-APACHE](./LICENSE-APACHE)) at your option.
