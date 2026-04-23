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
import { exaAuthDefinition, verifyExaAuth } from "./auth.ts";

const EXA_API_KEYS_BASE =
  process.env.EXA_API_KEYS_URL ?? "https://admin-api.exa.ai/team-management/api-keys";
const EXA_PROVIDER = "exa";

interface ExaApiKey {
  id?: string;
  name?: string;
  key?: string;
  apiKey?: string;
  token?: string;
  value?: string;
  secret?: string;
  rateLimit?: number;
  teamId?: string;
  userId?: string;
  createdAt?: string;
  lastUsedAt?: string | null;
}

interface ExaCreateApiKeyResponse {
  apiKey?: ExaApiKey;
  key?: string;
  token?: string;
  value?: string;
  secret?: string;
}

interface ExaListApiKeysResponse {
  apiKeys?: ExaApiKey[];
}

interface ExaOwnershipPreload extends Record<string, unknown> {
  provider: typeof EXA_PROVIDER;
  strategy: "api-introspection";
  team?: { id: string; name?: string };
  apiKeys: Array<{ id: string; name?: string; createdAt?: string; lastUsedAt?: string | null }>;
  error?: string;
}

export const adapterExaAdapter: Adapter = {
  name: EXA_PROVIDER,
  authRef: EXA_PROVIDER,
  authDefinition: exaAuthDefinition,
  // Exa's POST /team-management/api-keys creates a key but NEVER returns
  // the plaintext value — it's visible only once in the dashboard at
  // creation time. That makes auto-rotation impossible. Go manual-assist:
  // deep-link to the dashboard, prompt for the new key, propagate.
  mode: "manual-assist",

  async auth(): Promise<AuthContext> {
    return resolveRegisteredAuth(EXA_PROVIDER);
  },

  async create(spec: RotationSpec, _ctx: AuthContext): Promise<RotationResult<Secret>> {
    const io = spec.io;
    if (!io?.isInteractive) {
      return {
        ok: false,
        error: makeError(
          "unsupported",
          "Exa rotation is manual-assist — re-run with --manual-only from an interactive TTY",
          EXA_PROVIDER,
          { retryable: false },
        ),
      };
    }
    io.note(
      [
        "Exa API key rotation is manual-assist: the REST endpoint returns only key metadata,",
        "never the plaintext value. You need to copy it from the dashboard at creation time.",
        "",
        "Open: https://dashboard.exa.ai/api-keys",
        `Target: ${spec.secretId}`,
        "",
        "Steps:",
        "1. Create a new API key with a descriptive name.",
        "2. Copy the new key value (only shown once).",
        "3. Paste it below — rotate-cli propagates to every vercel-env consumer.",
        "4. After the grace period, delete the OLD key from the same dashboard page.",
      ].join("\n"),
    );
    const value = (await io.promptSecret("Paste the new Exa API key")).trim();
    if (!value) {
      return {
        ok: false,
        error: makeError("invalid_spec", "pasted Exa API key was empty", EXA_PROVIDER),
      };
    }
    return {
      ok: true,
      data: {
        id: spec.secretId,
        provider: EXA_PROVIDER,
        value,
        metadata: { ...spec.metadata, manual_assist: "true" },
        createdAt: new Date().toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    try {
      await verifyExaAuth({ kind: "env", varName: "EXA_API_KEY", token: secret.value });
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

  async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
    const keyId = secret.metadata.key_id ?? secret.id;
    const res = await request(`${EXA_API_KEYS_BASE}/${encodeURIComponent(keyId)}`, {
      method: "DELETE",
      headers: authHeaders(ctx.token),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (res.status === 404) return { ok: true, data: undefined };
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },

  async list(_filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const listed = await listApiKeys(ctx.token);
    if (listed instanceof Error) return { ok: false, error: networkError(listed) };
    if (listed instanceof Response) return { ok: false, error: fromResponse(listed, "list") };

    return {
      ok: true,
      data: listed.flatMap((key) => {
        if (!key.id) return [];
        return [
          {
            id: key.id,
            provider: EXA_PROVIDER,
            value: "<redacted>",
            metadata: keyMetadata(key),
            createdAt: key.createdAt ?? new Date(0).toISOString(),
          },
        ];
      }),
    };
  },

  async preloadOwnership(ctx: AuthContext): Promise<OwnershipPreload> {
    const listed = await listApiKeys(ctx.token);
    if (listed instanceof Error) return ownershipPreload([], undefined, "network_error");
    if (listed instanceof Response)
      return ownershipPreload([], undefined, errorCode(listed.status));

    const teamId = inferSingleTeamId(listed);
    return ownershipPreload(listed, teamId);
  },

  async ownedBy(
    secretValue: string,
    ctx: AuthContext,
    opts?: OwnershipOptions,
  ): Promise<OwnershipResult> {
    const candidate = await listApiKeys(secretValue);
    if (candidate instanceof Error) {
      return unknownOwnership("network error while reading Exa team-management API keys");
    }
    if (candidate instanceof Response) {
      if (candidate.status === 401 || candidate.status === 403) {
        return unknownOwnership("candidate key cannot access Exa team-management endpoints");
      }
      if (candidate.status === 429) return unknownOwnership("Exa rate limited the ownership check");
      if (candidate.status >= 500) return unknownOwnership("provider unavailable");
      return unknownOwnership(`Exa ownership endpoint returned ${candidate.status}`);
    }

    const adminPreload = isExaOwnershipPreload(opts?.preload)
      ? opts.preload
      : await adapterExaAdapter.preloadOwnership?.(ctx);
    const adminTeamId = isExaOwnershipPreload(adminPreload) ? adminPreload.team?.id : undefined;
    const candidateTeamId = inferSingleTeamId(candidate);

    if (candidateTeamId && adminTeamId) {
      if (candidateTeamId === adminTeamId) {
        return {
          verdict: "self",
          adminCanBill: true,
          scope: "team",
          confidence: "high",
          evidence: "Exa team-management introspection returned a team id matching the admin key",
          strategy: "api-introspection",
        };
      }
      return {
        verdict: "other",
        adminCanBill: false,
        scope: "team",
        confidence: "high",
        evidence: "Exa team-management introspection returned a different team id",
        strategy: "api-introspection",
      };
    }

    const adminKeyIds = new Set(
      isExaOwnershipPreload(adminPreload) ? adminPreload.apiKeys.map((key) => key.id) : [],
    );
    const candidateKeyIds = candidate.flatMap((key) => (key.id ? [key.id] : []));
    if (adminKeyIds.size > 0 && candidateKeyIds.some((id) => adminKeyIds.has(id))) {
      return {
        verdict: "self",
        adminCanBill: true,
        scope: "team",
        confidence: "medium",
        evidence: "candidate Exa key can list API keys that overlap the admin key inventory",
        strategy: "api-introspection",
      };
    }

    if (adminKeyIds.size > 0 && candidateKeyIds.length > 0) {
      return {
        verdict: "other",
        adminCanBill: false,
        scope: "team",
        confidence: "medium",
        evidence: "candidate Exa key inventory is disjoint from the admin key inventory",
        strategy: "api-introspection",
      };
    }

    return unknownOwnership("Exa ownership introspection returned no comparable team or key data");
  },
};

export default adapterExaAdapter;

function authHeaders(token: string): Record<string, string> {
  return {
    "x-api-key": token,
    "Content-Type": "application/json",
    "User-Agent": "rotate-cli/0.0.1",
  };
}

async function request(url: string, init: RequestInit): Promise<Response | Error> {
  try {
    return await fetch(url, init);
  } catch (cause) {
    return cause instanceof Error ? cause : new Error(String(cause));
  }
}

async function listApiKeys(token: string): Promise<ExaApiKey[] | Response | Error> {
  const res = await request(EXA_API_KEYS_BASE, {
    headers: authHeaders(token),
  });
  if (res instanceof Error) return res;
  if (!res.ok) return res;
  const body = (await res.json()) as ExaListApiKeysResponse;
  return body.apiKeys ?? [];
}

function apiKeyName(spec: RotationSpec): string {
  return (spec.metadata.name || `rotate-cli-${spec.secretId}-${Date.now()}`).slice(0, 100);
}

function parseRateLimit(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) return undefined;
  return parsed;
}

function plaintextKey(body: ExaCreateApiKeyResponse): string | undefined {
  const apiKey = body.apiKey;
  const candidates = [
    apiKey?.key,
    apiKey?.apiKey,
    apiKey?.token,
    apiKey?.value,
    apiKey?.secret,
    body.key,
    body.token,
    body.value,
    body.secret,
  ];
  return candidates.find((value): value is string => typeof value === "string" && value.length > 0);
}

function keyMetadata(key: ExaApiKey): Record<string, string> {
  return compactMetadata({
    key_id: key.id,
    name: key.name,
    rate_limit: numberMetadata(key.rateLimit),
    team_id: key.teamId,
    user_id: key.userId,
    last_used_at: key.lastUsedAt ?? undefined,
  });
}

function compactMetadata(input: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(input).filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
}

function numberMetadata(value: number | undefined): string | undefined {
  return typeof value === "number" ? String(value) : undefined;
}

function ownershipPreload(
  apiKeys: ExaApiKey[],
  teamId?: string,
  error?: string,
): ExaOwnershipPreload {
  return {
    provider: EXA_PROVIDER,
    strategy: "api-introspection",
    ...(teamId ? { team: { id: teamId } } : {}),
    apiKeys: apiKeys.flatMap((key) => {
      if (!key.id) return [];
      return [
        {
          id: key.id,
          name: key.name,
          createdAt: key.createdAt,
          lastUsedAt: key.lastUsedAt,
        },
      ];
    }),
    ...(error ? { error } : {}),
  };
}

function inferSingleTeamId(keys: ExaApiKey[]): string | undefined {
  const teamIds = new Set(
    keys.flatMap((key) => (typeof key.teamId === "string" && key.teamId ? [key.teamId] : [])),
  );
  return teamIds.size === 1 ? [...teamIds][0] : undefined;
}

function isExaOwnershipPreload(value: unknown): value is ExaOwnershipPreload {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as ExaOwnershipPreload).provider === EXA_PROVIDER &&
    Array.isArray((value as ExaOwnershipPreload).apiKeys)
  );
}

function unknownOwnership(evidence: string): OwnershipResult {
  return {
    verdict: "unknown",
    adminCanBill: false,
    scope: "team",
    confidence: "low",
    evidence,
    strategy: "api-introspection",
  };
}

function errorCode(status: number): string {
  if (status === 401 || status === 403) return "auth_failed";
  if (status === 429) return "rate_limited";
  if (status >= 500) return "provider_error";
  return "provider_error";
}

function networkError(cause: Error) {
  return makeError("network_error", `exa network error: ${cause.message}`, EXA_PROVIDER, { cause });
}

function fromResponse(res: Response, op: string) {
  return fromStatus(res.status, op);
}

function fromStatus(status: number, op: string) {
  if (status === 401 || status === 403) {
    return makeError("auth_failed", `exa ${op}: ${status}`, EXA_PROVIDER);
  }
  if (status === 429) return makeError("rate_limited", `exa ${op}: 429`, EXA_PROVIDER);
  if (status === 404) return makeError("not_found", `exa ${op}: 404`, EXA_PROVIDER);
  if (status >= 500) return makeError("provider_error", `exa ${op}: ${status}`, EXA_PROVIDER);
  return makeError("provider_error", `exa ${op}: ${status}`, EXA_PROVIDER, {
    retryable: false,
  });
}
