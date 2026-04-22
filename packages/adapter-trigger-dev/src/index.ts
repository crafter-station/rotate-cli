import { makeError } from "@rotate/core";
import { resolveRegisteredAuth } from "@rotate/core/auth";
import type {
  Adapter,
  AuthContext,
  OwnershipOptions,
  OwnershipResult,
  PromptIO,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";
import { triggerDevAuthDefinition, verifyTriggerDevAuth } from "./auth.ts";

const PROVIDER = "trigger-dev";
const DISPLAY_PROVIDER = "Trigger.dev";
const DASHBOARD_URL = "https://cloud.trigger.dev";

export const adapterTriggerDevAdapter: Adapter = {
  name: PROVIDER,
  authRef: PROVIDER,
  authDefinition: triggerDevAuthDefinition,
  mode: "manual-assist",

  async auth(): Promise<AuthContext> {
    return resolveRegisteredAuth(PROVIDER);
  },

  async create(spec: RotationSpec, _ctx: AuthContext): Promise<RotationResult<Secret>> {
    const io = spec.io;
    if (!io?.isInteractive) {
      return {
        ok: false,
        error: makeError(
          "unsupported",
          "trigger-dev create requires an interactive dashboard handoff",
          DISPLAY_PROVIDER,
        ),
      };
    }

    io.note(createInstructions(spec.metadata));
    const value = (await io.promptSecret("Paste the new Trigger.dev project secret key")).trim();
    if (!value) {
      return {
        ok: false,
        error: makeError(
          "invalid_spec",
          "trigger-dev create: pasted key was empty",
          DISPLAY_PROVIDER,
        ),
      };
    }

    return {
      ok: true,
      data: {
        id: spec.metadata.key_id ?? spec.secretId,
        provider: PROVIDER,
        value,
        metadata: compactMetadata({
          ...spec.metadata,
          rotation_mode: "manual-assist",
        }),
        createdAt: new Date().toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    try {
      await verifyTriggerDevAuth({
        kind: "env",
        varName: "TRIGGER_SECRET_KEY",
        token: secret.value,
      });
      return { ok: true, data: true };
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      const status = Number.parseInt(message.split(": ").at(-1) ?? "", 10);
      if (Number.isInteger(status)) {
        return { ok: false, error: fromStatus(status, "verify") };
      }
      return {
        ok: false,
        error: networkError(cause instanceof Error ? cause : new Error(message)),
      };
    }
  },

  async revoke(
    secret: Secret,
    _ctx: AuthContext,
    opts?: { io?: PromptIO },
  ): Promise<RotationResult<void>> {
    const io = opts?.io;
    if (!io?.isInteractive) {
      return {
        ok: false,
        error: makeError(
          "unsupported",
          "trigger-dev revoke requires an interactive dashboard handoff",
          DISPLAY_PROVIDER,
        ),
      };
    }

    io.note(revokeInstructions(secret));
    const confirmed = await io.confirm("Have you revoked the old Trigger.dev secret key?", {
      initialValue: false,
    });
    if (!confirmed) {
      return {
        ok: false,
        error: makeError(
          "unsupported",
          "trigger-dev revoke was not confirmed in the dashboard",
          DISPLAY_PROVIDER,
        ),
      };
    }
    return { ok: true, data: undefined };
  },

  async ownedBy(
    _value: string,
    _ctx: AuthContext,
    opts?: OwnershipOptions,
  ): Promise<OwnershipResult> {
    const hints = triggerMetadataHints(opts?.coLocatedVars);
    return {
      verdict: "unknown",
      adminCanBill: false,
      scope: hints ? "project" : undefined,
      confidence: "low",
      evidence: hints
        ? `Trigger.dev project/environment hints are present (${hints}), but project secret key ownership is not publicly introspectable`
        : "Trigger.dev project secret key ownership is not publicly introspectable",
      strategy: hints ? "sibling-inheritance" : "format-decode",
    };
  },
};

export default adapterTriggerDevAdapter;

function createInstructions(metadata: Record<string, string>): string {
  const hints = metadataHints(metadata);
  return [
    "Trigger.dev secret key rotation is dashboard-only.",
    `Open ${DASHBOARD_URL} and select the project${hints ? ` (${hints})` : ""}.`,
    "Choose the target environment, open API Keys, create or reveal a replacement Secret API key, then paste the new value here.",
    "Do not trigger a run or mutate project settings as part of this verification.",
  ].join("\n");
}

function revokeInstructions(secret: Secret): string {
  const hints = metadataHints(secret.metadata);
  return [
    "Revoke the old Trigger.dev project secret key in the dashboard.",
    `Open ${DASHBOARD_URL} and select the project${hints ? ` (${hints})` : ""}.`,
    "Choose the same environment, open API Keys, delete or revoke the old key after propagated consumers have verified the replacement.",
    `Old secret reference: ${secret.id}`,
  ].join("\n");
}

function metadataHints(metadata: Record<string, string>): string {
  const entries = [
    ["project_ref", metadata.project_ref],
    ["project_id", metadata.project_id],
    ["project_slug", metadata.project_slug],
    ["environment", metadata.environment],
    ["preview_branch", metadata.preview_branch],
  ].filter((entry): entry is [string, string] => Boolean(entry[1]));
  return entries.map(([key, value]) => `${key}=${value}`).join(", ");
}

function triggerMetadataHints(vars?: Record<string, string>): string {
  if (!vars) return "";
  return metadataHints(
    compactMetadata({
      project_ref: vars.TRIGGER_PROJECT_REF ?? vars.TRIGGER_PROJECT_ID,
      project_id: vars.TRIGGER_PROJECT_ID,
      project_slug: vars.TRIGGER_PROJECT_SLUG,
      environment: vars.TRIGGER_ENVIRONMENT ?? vars.TRIGGER_ENV,
      preview_branch: vars.TRIGGER_PREVIEW_BRANCH,
    }),
  );
}

function compactMetadata(metadata: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(metadata).filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
}

function fromStatus(status: number, op: string) {
  if (status === 401 || status === 403) {
    return makeError("auth_failed", `trigger-dev ${op}: ${status}`, DISPLAY_PROVIDER);
  }
  if (status === 429) return makeError("rate_limited", `trigger-dev ${op}: 429`, DISPLAY_PROVIDER);
  if (status >= 500) {
    return makeError("provider_error", `trigger-dev ${op}: ${status}`, DISPLAY_PROVIDER);
  }
  return makeError("provider_error", `trigger-dev ${op}: ${status}`, DISPLAY_PROVIDER, {
    retryable: false,
  });
}

function networkError(cause: Error) {
  return makeError(
    "network_error",
    `trigger-dev network error: ${cause.message}`,
    DISPLAY_PROVIDER,
    {
      cause,
    },
  );
}
