import { makeError } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

const POLAR_BASE = process.env.POLAR_API_URL ?? "https://api.polar.sh/v1";

interface PolarOrganizationAccessToken {
  id: string;
  created_at: string;
  modified_at?: string;
  organization_id: string;
  comment: string;
  scopes: string[];
  expires_at?: string | null;
  last_used_at?: string | null;
}

interface PolarOrganizationAccessTokenCreateResponse {
  organization_access_token: PolarOrganizationAccessToken;
  token: string;
}

interface PolarWebhookEndpoint {
  id: string;
  url?: string;
  secret?: string;
  events?: string[];
  format?: string;
  organization_id?: string;
  enabled?: boolean;
  created_at?: string;
  modified_at?: string;
}

interface PolarListResponse<T> {
  items?: T[];
  data?: T[];
}

type PolarKind = "oat" | "webhook";

export const polarAdapter: Adapter = {
  name: "polar",

  async auth(): Promise<AuthContext> {
    const envToken = process.env.POLAR_BOOTSTRAP_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "POLAR_BOOTSTRAP_TOKEN", token: envToken };
    }
    throw new Error("polar auth unavailable: set POLAR_BOOTSTRAP_TOKEN to a bootstrap OAT");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const kind = kindFromMetadata(spec.metadata);
    if (kind === "webhook") return createWebhookSecret(spec, ctx);
    return createOrganizationAccessToken(spec, ctx);
  },

  async verify(secret: Secret, ctx: AuthContext): Promise<RotationResult<boolean>> {
    const kind = kindFromMetadata(secret.metadata);
    if (kind === "webhook") return verifyWebhookSecret(secret, ctx);
    const res = await request(`${POLAR_BASE}/organization-access-tokens/?page=1&limit=1`, {
      headers: authHeaders(secret.value),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify", true) };
    return { ok: true, data: true };
  },

  async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
    const kind = kindFromMetadata(secret.metadata);
    if (kind === "webhook") return { ok: true, data: undefined };
    const tokenId = secret.metadata.token_id ?? secret.id;
    const res = await request(`${POLAR_BASE}/organization-access-tokens/${tokenId}`, {
      method: "DELETE",
      headers: authHeaders(ctx.token),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res, false) };
    if (res.status === 404) return { ok: true, data: undefined };
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke", false) };
    return { ok: true, data: undefined };
  },

  async list(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const kind = kindFromMetadata(filter);
    if (kind === "webhook") return listWebhookSecrets(filter, ctx);
    return listOrganizationAccessTokens(filter, ctx);
  },
};

export default polarAdapter;

async function createOrganizationAccessToken(
  spec: RotationSpec,
  ctx: AuthContext,
): Promise<RotationResult<Secret>> {
  const scopes = parseScopes(spec.metadata.scopes);
  if (scopes.length === 0) {
    return {
      ok: false,
      error: makeError(
        "invalid_spec",
        "metadata.scopes is required for Polar OAT rotation",
        "polar",
      ),
    };
  }
  const comment =
    spec.metadata.comment ?? `rotate-cli|${spec.secretId}|${new Date().toISOString()}`;
  const body = compactBody({
    comment,
    scopes,
    expires_in: spec.metadata.expires_in,
    organization_id: spec.metadata.organization_id,
  });
  const res = await request(`${POLAR_BASE}/organization-access-tokens/`, {
    method: "POST",
    headers: authHeaders(ctx.token),
    body: JSON.stringify(body),
  });
  if (res instanceof Error) return { ok: false, error: networkError(res) };
  if (!res.ok) return { ok: false, error: fromResponse(res, "create", true) };
  const data = (await res.json()) as PolarOrganizationAccessTokenCreateResponse;
  const token = data.organization_access_token;
  return {
    ok: true,
    data: {
      id: token.id,
      provider: "polar",
      value: data.token,
      metadata: compactMetadata({
        kind: "oat",
        token_id: token.id,
        organization_id: token.organization_id,
        comment: token.comment,
        scopes: token.scopes.join(","),
        last_used_at: token.last_used_at ?? undefined,
      }),
      createdAt: token.created_at,
      expiresAt: token.expires_at ?? undefined,
    },
  };
}

async function createWebhookSecret(
  spec: RotationSpec,
  ctx: AuthContext,
): Promise<RotationResult<Secret>> {
  const endpointId = spec.metadata.webhook_endpoint_id;
  if (!endpointId) {
    return {
      ok: false,
      error: makeError(
        "invalid_spec",
        "metadata.webhook_endpoint_id is required for Polar webhook rotation",
        "polar",
      ),
    };
  }
  const res = await request(`${POLAR_BASE}/webhooks/endpoints/${endpointId}/secret`, {
    method: "PATCH",
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) return { ok: false, error: networkError(res) };
  if (!res.ok) return { ok: false, error: fromResponse(res, "create", true) };
  const data = (await res.json()) as PolarWebhookEndpoint;
  if (!data.secret) {
    return {
      ok: false,
      error: makeError("provider_error", "polar create: response missing webhook secret", "polar", {
        retryable: false,
      }),
    };
  }
  return {
    ok: true,
    data: {
      id: data.id,
      provider: "polar",
      value: data.secret,
      metadata: compactMetadata({
        kind: "webhook",
        webhook_endpoint_id: data.id,
        organization_id: data.organization_id,
        url: data.url,
        format: data.format,
        events: data.events?.join(","),
        enabled: data.enabled === undefined ? undefined : String(data.enabled),
      }),
      createdAt: data.modified_at ?? data.created_at ?? new Date().toISOString(),
    },
  };
}

async function verifyWebhookSecret(
  secret: Secret,
  ctx: AuthContext,
): Promise<RotationResult<boolean>> {
  const endpointId = secret.metadata.webhook_endpoint_id ?? secret.id;
  const organizationId = secret.metadata.organization_id;
  const query = new URLSearchParams({ page: "1", limit: "100" });
  if (organizationId) query.set("organization_id", organizationId);
  const res = await request(`${POLAR_BASE}/webhooks/endpoints?${query.toString()}`, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) return { ok: false, error: networkError(res) };
  if (!res.ok) return { ok: false, error: fromResponse(res, "verify", true) };
  const body = (await res.json()) as PolarListResponse<PolarWebhookEndpoint>;
  const endpoint = listItems(body).find((item) => item.id === endpointId);
  if (!endpoint) {
    return {
      ok: false,
      error: makeError("not_found", "polar verify: webhook endpoint not found", "polar"),
    };
  }
  if (endpoint.secret && endpoint.secret !== secret.value) {
    return {
      ok: false,
      error: makeError("provider_error", "polar verify: webhook secret mismatch", "polar", {
        retryable: false,
      }),
    };
  }
  return { ok: true, data: true };
}

async function listOrganizationAccessTokens(
  filter: Record<string, string>,
  ctx: AuthContext,
): Promise<RotationResult<Secret[]>> {
  const query = new URLSearchParams({
    page: filter.page ?? "1",
    limit: filter.limit ?? "100",
    sorting: filter.sorting ?? "-created_at",
  });
  if (filter.organization_id) query.set("organization_id", filter.organization_id);
  const res = await request(`${POLAR_BASE}/organization-access-tokens/?${query.toString()}`, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) return { ok: false, error: networkError(res) };
  if (!res.ok) return { ok: false, error: fromResponse(res, "list", true) };
  const body = (await res.json()) as PolarListResponse<PolarOrganizationAccessToken>;
  const commentPrefix = filter.comment_prefix;
  const tokens = listItems(body).filter(
    (token) => !commentPrefix || token.comment.startsWith(commentPrefix),
  );
  return {
    ok: true,
    data: tokens.map((token) => ({
      id: token.id,
      provider: "polar",
      value: "<redacted>",
      metadata: compactMetadata({
        kind: "oat",
        token_id: token.id,
        organization_id: token.organization_id,
        comment: token.comment,
        scopes: token.scopes.join(","),
        last_used_at: token.last_used_at ?? undefined,
      }),
      createdAt: token.created_at,
      expiresAt: token.expires_at ?? undefined,
    })),
  };
}

async function listWebhookSecrets(
  filter: Record<string, string>,
  ctx: AuthContext,
): Promise<RotationResult<Secret[]>> {
  const query = new URLSearchParams({
    page: filter.page ?? "1",
    limit: filter.limit ?? "100",
  });
  if (filter.organization_id) query.set("organization_id", filter.organization_id);
  const res = await request(`${POLAR_BASE}/webhooks/endpoints?${query.toString()}`, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) return { ok: false, error: networkError(res) };
  if (!res.ok) return { ok: false, error: fromResponse(res, "list", true) };
  const body = (await res.json()) as PolarListResponse<PolarWebhookEndpoint>;
  const endpointId = filter.webhook_endpoint_id;
  const endpoints = listItems(body).filter((endpoint) => !endpointId || endpoint.id === endpointId);
  return {
    ok: true,
    data: endpoints.map((endpoint) => ({
      id: endpoint.id,
      provider: "polar",
      value: endpoint.secret ?? "<redacted>",
      metadata: compactMetadata({
        kind: "webhook",
        webhook_endpoint_id: endpoint.id,
        organization_id: endpoint.organization_id,
        url: endpoint.url,
        format: endpoint.format,
        events: endpoint.events?.join(","),
        enabled: endpoint.enabled === undefined ? undefined : String(endpoint.enabled),
      }),
      createdAt: endpoint.modified_at ?? endpoint.created_at ?? new Date(0).toISOString(),
    })),
  };
}

function authHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

async function request(url: string, init: RequestInit): Promise<Response | Error> {
  try {
    return await fetch(url, init);
  } catch (cause) {
    return cause instanceof Error ? cause : new Error(String(cause));
  }
}

function kindFromMetadata(metadata: Record<string, string>): PolarKind {
  return metadata.kind === "webhook" ? "webhook" : "oat";
}

function parseScopes(scopes?: string): string[] {
  return (
    scopes
      ?.split(",")
      .map((scope) => scope.trim())
      .filter(Boolean) ?? []
  );
}

function listItems<T>(body: PolarListResponse<T>): T[] {
  return body.items ?? body.data ?? [];
}

function compactMetadata(input: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(input).filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
}

function compactBody(input: Record<string, string | string[] | undefined>) {
  return Object.fromEntries(Object.entries(input).filter((entry) => entry[1] !== undefined));
}

function networkError(cause: Error, retryable = true) {
  return makeError("network_error", `polar network error: ${cause.message}`, "polar", {
    cause,
    retryable,
  });
}

function fromResponse(res: Response, op: string, retryDeleteErrors: boolean) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `polar ${op}: ${res.status}`, "polar");
  }
  if (res.status === 429) return makeError("rate_limited", `polar ${op}: 429`, "polar");
  if (res.status === 404) return makeError("not_found", `polar ${op}: 404`, "polar");
  if (res.status >= 500) {
    return makeError("provider_error", `polar ${op}: ${res.status}`, "polar", {
      retryable: retryDeleteErrors,
    });
  }
  return makeError("provider_error", `polar ${op}: ${res.status}`, "polar", {
    retryable: false,
  });
}
