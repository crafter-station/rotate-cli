import { makeError } from "@rotate/core";
import { resolveRegisteredAuth } from "@rotate/core/auth";
import type {
  Adapter,
  AuthContext,
  OwnershipOptions,
  OwnershipPreload,
  OwnershipResult,
  PromptIO,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";
import { uploadthingAuthDefinition, verifyUploadthingAuth } from "./auth.ts";

const PROVIDER = "uploadthing";
const DASHBOARD_URL = "https://uploadthing.com/dashboard";

interface UploadThingOwnershipPreload extends OwnershipPreload {
  apps?: Array<{ id: string; name?: string; teamId?: string }>;
}

export const adapterUploadthingAdapter: Adapter = {
  name: PROVIDER,
  authRef: PROVIDER,
  authDefinition: uploadthingAuthDefinition,
  mode: "manual-assist",

  async auth(): Promise<AuthContext> {
    return resolveRegisteredAuth(PROVIDER);
  },

  async create(spec: RotationSpec, _ctx: AuthContext): Promise<RotationResult<Secret>> {
    const io = spec.io;
    if (!io?.isInteractive) {
      return unsupported("create requires an interactive UploadThing dashboard session");
    }

    io.note(
      [
        `Open UploadThing: ${DASHBOARD_URL}`,
        "Select the app that owns this secret.",
        "Create or rotate the server token in the dashboard.",
        "Copy the newly displayed token. UploadThing may only show it once.",
      ].join("\n"),
    );

    const value = (await io.promptSecret("Paste the new UploadThing token")).trim();
    if (!value) {
      return {
        ok: false,
        error: makeError("invalid_spec", "uploadthing create: pasted token was empty", PROVIDER),
      };
    }

    const decoded = decodeUploadthingToken(value);
    return {
      ok: true,
      data: {
        id: secretId(spec, decoded?.appId),
        provider: PROVIDER,
        value,
        metadata: metadataFor({
          app_id: decoded?.appId,
          rotation_mode: "manual-assist",
        }),
        createdAt: new Date().toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    try {
      await verifyUploadthingAuth({
        kind: "env",
        varName: "UPLOADTHING_TOKEN",
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
      return unsupported("revoke requires an interactive UploadThing dashboard session");
    }

    const decoded = decodeUploadthingToken(secret.value);
    const appHint = secret.metadata.app_id ?? decoded?.appId;
    io.note(
      [
        `Open UploadThing: ${DASHBOARD_URL}`,
        appHint ? `Select app ${appHint}.` : "Select the app that owned the old token.",
        "Find the old server token and revoke or delete it in the dashboard.",
        "Confirm below only after the old token is no longer usable.",
      ].join("\n"),
    );

    const confirmed = await io.confirm("Have you revoked the old UploadThing token?", {
      initialValue: false,
    });
    if (!confirmed) {
      return {
        ok: false,
        error: makeError("unsupported", "uploadthing revoke was not confirmed", PROVIDER),
      };
    }

    return { ok: true, data: undefined };
  },

  async ownedBy(
    secretValue: string,
    _ctx: AuthContext,
    opts?: OwnershipOptions,
  ): Promise<OwnershipResult> {
    const decoded = decodeUploadthingToken(secretValue);
    const siblingAppId = clean(opts?.coLocatedVars?.UPLOADTHING_APP_ID);
    const knownAppIds = appIdsFromPreload(opts?.preload);

    if (decoded?.appId && siblingAppId && decoded.appId === siblingAppId) {
      return {
        verdict: "self",
        adminCanBill: true,
        scope: "project",
        confidence: "medium",
        evidence: "UploadThing token app id matches co-located UPLOADTHING_APP_ID",
        strategy: "format-decode",
      };
    }

    if (decoded?.appId && knownAppIds?.has(decoded.appId)) {
      return {
        verdict: "self",
        adminCanBill: true,
        scope: "project",
        confidence: "medium",
        evidence: "UploadThing token app id matches admin preload",
        strategy: "format-decode",
      };
    }

    if (!decoded?.appId && siblingAppId && looksLikeLegacySecret(secretValue)) {
      return {
        verdict: "self",
        adminCanBill: true,
        scope: "project",
        confidence: "low",
        evidence: "legacy UploadThing secret ownership inferred from co-located UPLOADTHING_APP_ID",
        strategy: "sibling-inheritance",
      };
    }

    if (decoded?.appId && siblingAppId && decoded.appId !== siblingAppId) {
      return unknownOwnership("UploadThing token app id did not match co-located app id");
    }

    if (decoded?.appId) {
      return unknownOwnership(
        "UploadThing token app id decoded, but no complete admin app list exists",
      );
    }

    return unknownOwnership("UploadThing token format did not expose an app id");
  },
};

export default adapterUploadthingAdapter;

function secretId(spec: RotationSpec, appId: string | undefined): string {
  return appId ? `${spec.secretId}:${appId}` : spec.secretId;
}

function metadataFor(input: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(input).filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
}

function unsupported(message: string): RotationResult<never> {
  return {
    ok: false,
    error: makeError("unsupported", message, "UploadThing"),
  };
}

function appIdsFromPreload(preload: OwnershipPreload | undefined): Set<string> | undefined {
  const apps = (preload as UploadThingOwnershipPreload | undefined)?.apps;
  if (!Array.isArray(apps)) return undefined;
  return new Set(apps.flatMap((app) => (typeof app.id === "string" ? [app.id] : [])));
}

function unknownOwnership(evidence: string): OwnershipResult {
  return {
    verdict: "unknown",
    adminCanBill: false,
    scope: "project",
    confidence: "low",
    evidence,
    strategy: "format-decode",
  };
}

function looksLikeLegacySecret(value: string): boolean {
  const trimmed = value.trim();
  return trimmed.length > 0 && !decodeUploadthingToken(trimmed)?.appId;
}

function decodeUploadthingToken(value: string): { appId?: string } | undefined {
  const trimmed = value.trim();
  if (!trimmed) return undefined;

  const direct = parseTokenObject(trimmed);
  if (direct?.appId) return direct;

  const regexAppId = /"app[_-]?id"\s*:\s*"([^"]+)"/i.exec(trimmed)?.[1];
  if (regexAppId) return { appId: regexAppId };

  for (const candidate of tokenDecodeCandidates(trimmed)) {
    const decoded = decodeBase64Url(candidate);
    if (!decoded) continue;
    const parsed = parseTokenObject(decoded);
    if (parsed?.appId) return parsed;
    const nested = /"app[_-]?id"\s*:\s*"([^"]+)"/i.exec(decoded)?.[1];
    if (nested) return { appId: nested };
  }

  return undefined;
}

function tokenDecodeCandidates(value: string): string[] {
  const parts = value.split(/[._:-]/g).filter(Boolean);
  return [...new Set([value, ...parts, ...parts.map((part) => stripKnownPrefix(part))])].filter(
    Boolean,
  );
}

function stripKnownPrefix(value: string): string {
  return value.replace(/^(sk|pk|live|test|dev)_/i, "");
}

function parseTokenObject(value: string): { appId?: string } | undefined {
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    const appId = clean(
      parsed.appId ??
        parsed.app_id ??
        parsed.appID ??
        parsed.applicationId ??
        parsed.application_id,
    );
    return appId ? { appId } : undefined;
  } catch {
    return undefined;
  }
}

function decodeBase64Url(value: string): string | undefined {
  try {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
    return Buffer.from(padded, "base64").toString("utf8");
  } catch {
    return undefined;
  }
}

function clean(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function networkError(cause: Error) {
  return makeError("network_error", `uploadthing network error: ${cause.message}`, PROVIDER, {
    cause,
  });
}

function fromStatus(status: number, op: string) {
  if (status === 401 || status === 403) {
    return makeError("auth_failed", `uploadthing ${op}: ${status}`, PROVIDER);
  }
  if (status === 429) return makeError("rate_limited", `uploadthing ${op}: 429`, PROVIDER);
  if (status >= 500) {
    return makeError("provider_error", `uploadthing ${op}: ${status}`, PROVIDER);
  }
  return makeError("provider_error", `uploadthing ${op}: ${status}`, PROVIDER, {
    retryable: false,
  });
}
