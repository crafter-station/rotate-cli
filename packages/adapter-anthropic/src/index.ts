import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { makeError } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  OwnershipOptions,
  OwnershipPreload,
  OwnershipResult,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

const ANTHROPIC_BASE = process.env.ANTHROPIC_API_URL ?? "https://api.anthropic.com";
const API_KEYS_PATH = "/v1/organizations/api_keys";
const ORG_ME_PATH = "/v1/organizations/me";
const ANTHROPIC_VERSION = "2023-06-01";
const CLOSE_TIME_MS = 2 * 60 * 1000;

interface AnthropicApiKey {
  id?: string;
  name?: string;
  api_key?: string;
  key?: string;
  secret?: string;
  value?: string;
  partial_key?: string;
  created_at?: string;
  createdAt?: string;
  workspace_id?: string;
  status?: string;
}

interface AnthropicListResponse {
  data?: AnthropicApiKey[];
  has_more?: boolean;
  last_id?: string;
}

interface AnthropicOrgResponse {
  id?: string;
  name?: string;
}

interface AnthropicOwnershipKey {
  id: string;
  name?: string;
  workspaceId?: string;
  createdAt?: string;
  partialKey?: string;
  status?: string;
}

interface AnthropicOwnershipPreload extends OwnershipPreload {
  org?: {
    id?: string;
    name?: string;
  };
  keys?: AnthropicOwnershipKey[];
  error?: {
    code: string;
    message: string;
  };
}

export const anthropicAdapter: Adapter = {
  name: "anthropic",

  async auth(): Promise<AuthContext> {
    for (const path of candidateAuthPaths()) {
      if (!existsSync(path)) continue;
      try {
        const data = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
        const token = firstString(data, ["admin_key", "api_key", "token", "key"]);
        if (token) {
          return { kind: "cli-piggyback", tool: "anthropic", tokenPath: path, token };
        }
      } catch {}
    }
    const envToken = process.env.ANTHROPIC_ADMIN_KEY;
    if (envToken) {
      return { kind: "env", varName: "ANTHROPIC_ADMIN_KEY", token: envToken };
    }
    throw new Error("anthropic auth unavailable: set ANTHROPIC_ADMIN_KEY");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const name = spec.metadata.name ?? `rotate-cli-${spec.secretId}-${Date.now()}`;
    const body: Record<string, string> = { name };
    if (spec.metadata.workspace_id) body.workspace_id = spec.metadata.workspace_id;

    const res = await request(`${ANTHROPIC_BASE}${API_KEYS_PATH}`, {
      method: "POST",
      headers: authHeaders(ctx.token),
      body: JSON.stringify(body),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };

    const data = (await res.json()) as AnthropicApiKey;
    const keyId = data.id;
    const value = data.api_key ?? data.key ?? data.secret ?? data.value;
    if (!keyId || !value) {
      return {
        ok: false,
        error: makeError(
          "provider_error",
          "anthropic create: missing id or secret in response",
          "anthropic",
          { retryable: false },
        ),
      };
    }

    return {
      ok: true,
      data: {
        id: keyId,
        provider: "anthropic",
        value,
        metadata: metadataFor(data, keyId),
        createdAt: data.created_at ?? data.createdAt ?? new Date().toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    const res = await request(`${ANTHROPIC_BASE}${API_KEYS_PATH}?limit=1`, {
      headers: authHeaders(secret.value),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
    const keyId = secret.metadata.key_id ?? secret.id;
    const res = await request(`${ANTHROPIC_BASE}${API_KEYS_PATH}/${keyId}`, {
      method: "DELETE",
      headers: authHeaders(ctx.token),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (res.status === 404) return { ok: true, data: undefined };
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },

  async list(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const params = new URLSearchParams();
    if (filter.limit) params.set("limit", filter.limit);
    if (filter.workspace_id) params.set("workspace_id", filter.workspace_id);
    const qs = params.size > 0 ? `?${params.toString()}` : "";
    const res = await request(`${ANTHROPIC_BASE}${API_KEYS_PATH}${qs}`, {
      headers: authHeaders(ctx.token),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "list") };
    const body = (await res.json()) as AnthropicListResponse;
    return {
      ok: true,
      data: (body.data ?? []).flatMap((key) => {
        if (!key.id) return [];
        return [
          {
            id: key.id,
            provider: "anthropic",
            value: "<redacted>",
            metadata: metadataFor(key, key.id),
            createdAt: key.created_at ?? key.createdAt ?? new Date(0).toISOString(),
          },
        ];
      }),
    };
  },

  async preloadOwnership(ctx: AuthContext): Promise<OwnershipPreload> {
    const orgRes = await request(`${ANTHROPIC_BASE}${ORG_ME_PATH}`, {
      headers: authHeaders(ctx.token),
    });
    if (orgRes instanceof Error) return preloadError(networkError(orgRes));
    if (!orgRes.ok) return preloadError(fromResponse(orgRes, "ownership preload"));

    const org = (await orgRes.json()) as AnthropicOrgResponse;
    const keys: AnthropicOwnershipKey[] = [];
    let afterId: string | undefined;

    for (;;) {
      const params = new URLSearchParams({ limit: "1000", status: "active" });
      if (afterId) params.set("after_id", afterId);
      const res = await request(`${ANTHROPIC_BASE}${API_KEYS_PATH}?${params.toString()}`, {
        headers: authHeaders(ctx.token),
      });
      if (res instanceof Error) return preloadError(networkError(res), org);
      if (!res.ok) return preloadError(fromResponse(res, "ownership preload"), org);

      const body = (await res.json()) as AnthropicListResponse;
      for (const key of body.data ?? []) {
        if (!key.id) continue;
        keys.push({
          id: key.id,
          name: key.name,
          workspaceId: key.workspace_id,
          createdAt: key.created_at ?? key.createdAt,
          partialKey: key.partial_key,
          status: key.status,
        });
      }

      if (!body.has_more) break;
      afterId = body.last_id ?? body.data?.at(-1)?.id;
      if (!afterId) break;
    }

    return { org: { id: org.id, name: org.name }, keys } satisfies AnthropicOwnershipPreload;
  },

  async ownedBy(
    secretValue: string,
    ctx: AuthContext,
    opts: OwnershipOptions = {},
  ): Promise<OwnershipResult> {
    if (secretValue.startsWith("sk-ant-oat01-")) {
      return ownershipResult(
        "unknown",
        false,
        "low",
        "OAuth-subject Anthropic keys are not organization API keys and should not normally be stored in Vercel env vars.",
        "format-decode",
      );
    }

    if (!isAnthropicApiKey(secretValue)) {
      return ownershipResult(
        "unknown",
        false,
        "low",
        "Secret does not match a known Anthropic API key format.",
        "format-decode",
      );
    }

    const preload =
      (opts.preload as AnthropicOwnershipPreload | undefined) ??
      ((await anthropicAdapter.preloadOwnership?.(ctx)) as AnthropicOwnershipPreload | undefined);

    if (preload?.error) {
      return ownershipResult(
        "unknown",
        false,
        preload.error.code === "rate_limited" ? "low" : "medium",
        preload.error.message,
        "list-match",
      );
    }

    const keys = preload?.keys ?? [];
    const envVarName = envVarNameFor(secretValue, opts.coLocatedVars);
    const envCreatedAt = createdAtFor(envVarName, opts.coLocatedVars, preload);
    const matches = keys.filter((key) =>
      matchesOwnershipKey(secretValue, key, envVarName, envCreatedAt),
    );

    if (matches.length > 0) {
      const keyNames = uniqueStrings(matches.map((key) => key.name).filter(isString));
      const orgName = preload?.org?.name;
      const evidenceParts = [
        `Matched ${matches.length} active Anthropic API key record${matches.length === 1 ? "" : "s"} by admin list correlation`,
      ];
      if (orgName) evidenceParts.push(`org ${orgName}`);
      if (keyNames.length > 0) evidenceParts.push(`key name ${keyNames.join(", ")}`);

      return ownershipResult(
        "self",
        true,
        "medium",
        `${evidenceParts.join("; ")}.`,
        "list-match",
        "org",
      );
    }

    const siblingOwnership = siblingOwnershipFor(opts.coLocatedVars, preload);
    if (siblingOwnership === "self") {
      return ownershipResult(
        "self",
        false,
        "low",
        "Inferred from sibling env vars in the same Vercel context; Anthropic does not expose org identity for standard API keys.",
        "sibling-inheritance",
        "project",
      );
    }
    if (siblingOwnership === "other") {
      return ownershipResult(
        "other",
        false,
        "low",
        "Sibling env vars in the same Vercel context resolved to another owner; Anthropic key ownership is inferred.",
        "sibling-inheritance",
        "project",
      );
    }

    if (keys.length > 0) {
      return ownershipResult(
        "other",
        false,
        "low",
        "No matching Anthropic API key record was found in the authenticated admin key list.",
        "list-match",
        "org",
      );
    }

    return ownershipResult(
      "unknown",
      false,
      "low",
      "Anthropic admin key list was empty or unavailable, and no sibling ownership signal was provided.",
      "list-match",
    );
  },
};

export default anthropicAdapter;

function authHeaders(token: string): Record<string, string> {
  return {
    "Content-Type": "application/json",
    "anthropic-version": ANTHROPIC_VERSION,
    "x-api-key": token,
  };
}

async function request(url: string, init: RequestInit): Promise<Response | Error> {
  try {
    return await fetch(url, init);
  } catch (cause) {
    return cause instanceof Error ? cause : new Error(String(cause));
  }
}

function candidateAuthPaths(): string[] {
  const home = homedir();
  return [
    join(home, ".anthropic", "auth.json"),
    join(home, ".anthropic", "credentials.json"),
    join(home, ".config", "anthropic", "auth.json"),
    join(home, ".config", "anthropic", "credentials.json"),
  ];
}

function firstString(data: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = data[key];
    if (typeof value === "string" && value.length > 0) return value;
  }
  return undefined;
}

function metadataFor(data: AnthropicApiKey, keyId: string): Record<string, string> {
  const metadata: Record<string, string> = { key_id: keyId };
  if (data.name) metadata.name = data.name;
  if (data.partial_key) metadata.partial_key = data.partial_key;
  if (data.workspace_id) metadata.workspace_id = data.workspace_id;
  if (data.status) metadata.status = data.status;
  return metadata;
}

function networkError(cause: Error) {
  return makeError("network_error", `anthropic network error: ${cause.message}`, "anthropic", {
    cause,
  });
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `anthropic ${op}: ${res.status}`, "anthropic");
  }
  if (res.status === 429) return makeError("rate_limited", `anthropic ${op}: 429`, "anthropic");
  if (res.status === 404) return makeError("not_found", `anthropic ${op}: 404`, "anthropic");
  if (res.status >= 500) {
    return makeError("provider_error", `anthropic ${op}: ${res.status}`, "anthropic");
  }
  return makeError("provider_error", `anthropic ${op}: ${res.status}`, "anthropic", {
    retryable: false,
  });
}

function preloadError(
  error: ReturnType<typeof networkError> | ReturnType<typeof fromResponse>,
  org?: AnthropicOrgResponse,
): AnthropicOwnershipPreload {
  const message =
    error.code === "rate_limited"
      ? "Anthropic ownership preload was rate limited."
      : error.code === "provider_error"
        ? "Anthropic provider unavailable during ownership preload."
        : error.message;
  return {
    org: org ? { id: org.id, name: org.name } : undefined,
    keys: [],
    error: { code: error.code, message },
  };
}

function ownershipResult(
  verdict: OwnershipResult["verdict"],
  adminCanBill: boolean,
  confidence: OwnershipResult["confidence"],
  evidence: string,
  strategy: OwnershipResult["strategy"],
  scope?: OwnershipResult["scope"],
): OwnershipResult {
  return { verdict, adminCanBill, confidence, evidence, strategy, scope };
}

function isAnthropicApiKey(value: string): boolean {
  return value.startsWith("sk-ant-api03-") || value.startsWith("sk-ant-api-");
}

function matchesOwnershipKey(
  secretValue: string,
  key: AnthropicOwnershipKey,
  envVarName?: string,
  envCreatedAt?: string,
): boolean {
  if (key.partialKey && matchesPartialKey(secretValue, key.partialKey)) return true;
  if (envVarName && key.name && looselyMatches(key.name, envVarName)) return true;
  if (envCreatedAt && key.createdAt && closeInTime(key.createdAt, envCreatedAt, CLOSE_TIME_MS)) {
    return true;
  }
  return false;
}

function matchesPartialKey(secretValue: string, partialKey: string): boolean {
  const normalized = partialKey.trim();
  if (normalized.length === 0) return false;
  if (secretValue.includes(normalized)) return true;
  const parts = normalized
    .split("...")
    .map((part) => part.trim())
    .filter(Boolean);
  if (parts.length === 2)
    return secretValue.startsWith(parts[0] ?? "") && secretValue.endsWith(parts[1] ?? "");
  return false;
}

function looselyMatches(left: string, right: string): boolean {
  const rawA = compactName(left);
  const rawB = compactName(right);
  if (rawA && rawB && rawA === rawB) return true;
  const a = normalizeName(left);
  const b = normalizeName(right);
  if (!a || !b) return false;
  return a === b || a.includes(b) || b.includes(a);
}

function normalizeName(value: string): string {
  return compactName(value)
    .replace(/^anthropic/, "")
    .replace(/api/g, "")
    .replace(/key/g, "");
}

function compactName(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "");
}

function closeInTime(left: string, right: string, toleranceMs: number): boolean {
  const a = Date.parse(left);
  const b = Date.parse(right);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return false;
  return Math.abs(a - b) <= toleranceMs;
}

function envVarNameFor(
  secretValue: string,
  coLocatedVars: Record<string, string> | undefined,
): string | undefined {
  if (!coLocatedVars) return undefined;
  for (const [name, value] of Object.entries(coLocatedVars)) {
    if (value === secretValue) return name;
  }
  return undefined;
}

function createdAtFor(
  envVarName: string | undefined,
  coLocatedVars: Record<string, string> | undefined,
  preload: AnthropicOwnershipPreload | undefined,
): string | undefined {
  const preloadCreatedAt = firstPreloadString(preload, ["envCreatedAt", "createdAt"]);
  if (preloadCreatedAt) return preloadCreatedAt;
  if (!envVarName || !coLocatedVars) return undefined;
  return (
    coLocatedVars[`${envVarName}_CREATED_AT`] ??
    coLocatedVars[`${envVarName}_UPDATED_AT`] ??
    coLocatedVars.__createdAt ??
    coLocatedVars.__updatedAt
  );
}

function siblingOwnershipFor(
  coLocatedVars: Record<string, string> | undefined,
  preload: AnthropicOwnershipPreload | undefined,
): "self" | "other" | "unknown" {
  const preloadSignal = firstPreloadString(preload, [
    "vercelSiblingOwnership",
    "siblingOwnership",
    "siblingVerdict",
  ]);
  if (isOwnershipSignal(preloadSignal)) return preloadSignal;
  if (!coLocatedVars) return "unknown";

  for (const [name, value] of Object.entries(coLocatedVars)) {
    const normalized = name.toLowerCase();
    if (
      normalized.includes("ownership") &&
      (normalized.includes("clerk") ||
        normalized.includes("openai") ||
        normalized.includes("sibling")) &&
      isOwnershipSignal(value)
    ) {
      return value;
    }
  }

  return "unknown";
}

function firstPreloadString(
  preload: AnthropicOwnershipPreload | undefined,
  keys: string[],
): string | undefined {
  if (!preload) return undefined;
  for (const key of keys) {
    const value = preload[key];
    if (typeof value === "string" && value.length > 0) return value;
  }
  return undefined;
}

function isOwnershipSignal(value: unknown): value is "self" | "other" | "unknown" {
  return value === "self" || value === "other" || value === "unknown";
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values)];
}

function isString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}
