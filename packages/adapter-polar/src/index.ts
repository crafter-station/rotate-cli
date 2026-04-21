import { makeError } from "@rotate/core";
import { resolveRegisteredAuth } from "@rotate/core/auth";
import type {
  Adapter,
  AuthContext,
  OwnershipPreload,
  OwnershipResult,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";
import { polarAuthDefinition } from "./auth.ts";

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

interface PolarOrganization {
  id: string;
}

interface PolarOwnedResource {
  organization_id?: string;
}

interface PolarOwnershipPreload extends OwnershipPreload {
  knownOrgIds: string[];
  webhookSecretOrgIds: Record<string, string>;
}

interface NormalizedPolarOwnershipPreload {
  knownOrgIds: Set<string>;
  webhookSecretOrgIds: Record<string, string>;
}

type PolarKind = "oat" | "webhook";

export const polarAdapter: Adapter = {
  name: "polar",
  authRef: "polar",
  authDefinition: polarAuthDefinition,

  async auth(): Promise<AuthContext> {
    return resolveRegisteredAuth("polar");
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

  async ownedBy(secretValue: string, ctx: AuthContext, opts): Promise<OwnershipResult> {
    if (secretValue.startsWith("polar_whs_")) {
      const preload =
        normalizeOwnershipPreload(opts?.preload) ??
        normalizeOwnershipPreload(await buildOwnershipPreload(ctx));
      if (!preload) {
        return ownershipResult(
          "unknown",
          false,
          "low",
          "Could not load Polar webhook ownership index",
          "list-match",
        );
      }
      const orgId = preload.webhookSecretOrgIds[secretValue];
      if (!orgId) {
        return ownershipResult(
          "unknown",
          false,
          "low",
          "Polar webhook secret was not found in readable webhook endpoints",
          "list-match",
        );
      }
      const self = preload.knownOrgIds.has(orgId);
      return ownershipResult(
        self ? "self" : "other",
        self,
        "low",
        self
          ? "Polar webhook secret matched a readable endpoint in an admin organization"
          : "Polar webhook secret matched a readable endpoint outside the admin organization set",
        "list-match",
      );
    }

    if (isPolarBearer(secretValue)) {
      const knownOrgIds =
        normalizeOwnershipPreload(opts?.preload)?.knownOrgIds ??
        (await fetchKnownOrgIds(ctx.token));
      if (!knownOrgIds) {
        return ownershipResult(
          "unknown",
          false,
          "low",
          "Could not load Polar admin organizations",
          "api-introspection",
        );
      }
      const probe = await probeBearerOrganizationIds(secretValue);
      if (probe.status !== "ok") {
        return ownershipResult("unknown", false, "low", probe.evidence, "api-introspection");
      }
      if (probe.organizationIds.length === 0) {
        return ownershipResult(
          "unknown",
          false,
          "low",
          "Polar bearer probe returned no organizations",
          "api-introspection",
        );
      }
      const self = probe.organizationIds.some((id) => knownOrgIds.has(id));
      return ownershipResult(
        self ? "self" : "other",
        self,
        "high",
        self
          ? "Polar bearer probe returned an organization visible to the admin token"
          : "Polar bearer probe returned organizations outside the admin organization set",
        "api-introspection",
      );
    }

    return ownershipResult(
      "unknown",
      false,
      "low",
      "Secret does not match a known Polar credential prefix",
      "api-introspection",
    );
  },

  async preloadOwnership(ctx: AuthContext): Promise<OwnershipPreload> {
    return buildOwnershipPreload(ctx);
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

async function buildOwnershipPreload(ctx: AuthContext): Promise<PolarOwnershipPreload> {
  const knownOrgIds = await fetchKnownOrgIds(ctx.token);
  if (!knownOrgIds) return { knownOrgIds: [], webhookSecretOrgIds: {} };
  const webhookSecretOrgIds: Record<string, string> = {};
  for (const orgId of knownOrgIds) {
    const query = new URLSearchParams({ organization_id: orgId, page: "1", limit: "100" });
    const res = await request(`${POLAR_BASE}/webhooks/endpoints?${query.toString()}`, {
      headers: authHeaders(ctx.token),
    });
    if (res instanceof Error || !res.ok) continue;
    const body = await parseListResponse<PolarWebhookEndpoint>(res);
    if (!body) continue;
    for (const endpoint of listItems(body)) {
      if (isPlainWebhookSecret(endpoint.secret) && endpoint.organization_id) {
        webhookSecretOrgIds[endpoint.secret] = endpoint.organization_id;
      }
    }
  }
  return { knownOrgIds: [...knownOrgIds], webhookSecretOrgIds };
}

async function fetchKnownOrgIds(token: string): Promise<Set<string> | undefined> {
  const res = await request(`${POLAR_BASE}/organizations/`, {
    headers: authHeaders(token),
  });
  if (res instanceof Error || !res.ok) return undefined;
  const body = await parseListResponse<PolarOrganization>(res);
  if (!body) return undefined;
  return new Set(
    listItems(body)
      .map((org) => org.id)
      .filter(Boolean),
  );
}

async function probeBearerOrganizationIds(
  token: string,
): Promise<{ status: "ok"; organizationIds: string[] } | { status: "unknown"; evidence: string }> {
  const orgProbe = await request(`${POLAR_BASE}/organizations/`, {
    headers: authHeaders(token),
  });
  if (orgProbe instanceof Error) {
    return { status: "unknown", evidence: "Polar bearer probe failed due to a network error" };
  }
  if (orgProbe.ok) {
    const body = await parseListResponse<PolarOrganization>(orgProbe);
    if (!body) {
      return { status: "unknown", evidence: "Polar bearer probe returned invalid JSON" };
    }
    return {
      status: "ok",
      organizationIds: listItems(body)
        .map((org) => org.id)
        .filter(Boolean),
    };
  }
  if (orgProbe.status === 403) {
    return probeBearerResourceOrganizationIds(token);
  }
  return { status: "unknown", evidence: ownershipFailureEvidence(orgProbe, "bearer probe") };
}

async function probeBearerResourceOrganizationIds(
  token: string,
): Promise<{ status: "ok"; organizationIds: string[] } | { status: "unknown"; evidence: string }> {
  for (const path of ["customers", "products"]) {
    const res = await request(`${POLAR_BASE}/${path}/?limit=1`, {
      headers: authHeaders(token),
    });
    if (res instanceof Error) {
      return { status: "unknown", evidence: "Polar bearer fallback failed due to a network error" };
    }
    if (res.ok) {
      const body = await parseListResponse<PolarOwnedResource>(res);
      if (!body) {
        return { status: "unknown", evidence: "Polar bearer fallback returned invalid JSON" };
      }
      return {
        status: "ok",
        organizationIds: listItems(body)
          .map((resource) => resource.organization_id)
          .filter((id): id is string => Boolean(id)),
      };
    }
    if (res.status !== 403) {
      return { status: "unknown", evidence: ownershipFailureEvidence(res, "bearer fallback") };
    }
  }
  return {
    status: "unknown",
    evidence: "Polar bearer probe could not read organizations, customers, or products",
  };
}

async function parseListResponse<T>(res: Response): Promise<PolarListResponse<T> | undefined> {
  try {
    return (await res.json()) as PolarListResponse<T>;
  } catch {
    return undefined;
  }
}

function normalizeOwnershipPreload(
  preload: OwnershipPreload | undefined,
): NormalizedPolarOwnershipPreload | undefined {
  const raw = preload as PolarOwnershipPreload | undefined;
  if (!raw || !Array.isArray(raw.knownOrgIds)) return undefined;
  return {
    knownOrgIds: new Set(raw.knownOrgIds.filter((id): id is string => typeof id === "string")),
    webhookSecretOrgIds:
      raw.webhookSecretOrgIds && typeof raw.webhookSecretOrgIds === "object"
        ? raw.webhookSecretOrgIds
        : {},
  };
}

function ownershipResult(
  verdict: OwnershipResult["verdict"],
  adminCanBill: boolean,
  confidence: OwnershipResult["confidence"],
  evidence: string,
  strategy: OwnershipResult["strategy"],
): OwnershipResult {
  return {
    verdict,
    adminCanBill,
    scope: "org",
    confidence,
    evidence,
    strategy,
  };
}

function ownershipFailureEvidence(res: Response, op: string): string {
  if (res.status === 401 || res.status === 403) {
    makeError("auth_failed", `polar ownership ${op}: ${res.status}`, "polar");
    return "Polar ownership check could not authenticate the credential";
  }
  if (res.status === 429) {
    makeError("rate_limited", `polar ownership ${op}: 429`, "polar");
    return "Polar ownership check was rate limited";
  }
  if (res.status >= 500) {
    makeError("provider_error", `polar ownership ${op}: ${res.status}`, "polar");
    return "provider unavailable";
  }
  makeError("provider_error", `polar ownership ${op}: ${res.status}`, "polar");
  return "Polar ownership check returned an unexpected provider response";
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

function isPolarBearer(secretValue: string): boolean {
  return /^polar_(oat|at_[uo]|pat)_/.test(secretValue);
}

function isPlainWebhookSecret(secretValue: unknown): secretValue is string {
  return typeof secretValue === "string" && /^polar_whs_[A-Za-z0-9_-]+$/.test(secretValue);
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
