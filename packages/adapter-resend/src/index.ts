import { makeError } from "@rotate/core";
import { resolveRegisteredAuth } from "@rotate/core/auth";
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
import { resendAuthDefinition, verifyResendAuth } from "./auth.ts";

const RESEND_API_KEYS_BASE = process.env.RESEND_API_KEYS_URL ?? "https://api.resend.com/api-keys";
const RESEND_DOMAINS_BASE = process.env.RESEND_DOMAINS_URL ?? "https://api.resend.com/domains";
const RESEND_PROVIDER = "resend";

interface ResendCreateApiKeyResponse {
  id?: string;
  token?: string;
}

interface ResendApiKeyEntry {
  id?: string;
  name?: string;
  created_at?: string;
  last_used_at?: string | null;
}

interface ResendListApiKeysResponse {
  data?: ResendApiKeyEntry[];
}

interface ResendDomainEntry {
  id?: string;
  name?: string;
}

interface ResendListDomainsResponse {
  data?: ResendDomainEntry[];
}

export const resendAdapter: Adapter = {
  name: RESEND_PROVIDER,
  authRef: RESEND_PROVIDER,
  authDefinition: resendAuthDefinition,

  async auth(): Promise<AuthContext> {
    return resolveRegisteredAuth(RESEND_PROVIDER);
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const permission = spec.metadata.permission;
    if (permission && permission !== "full_access" && permission !== "sending_access") {
      return {
        ok: false,
        error: makeError(
          "invalid_spec",
          "metadata.permission must be full_access or sending_access",
          RESEND_PROVIDER,
        ),
      };
    }

    const name = apiKeyName(spec);
    const body: Record<string, string> = { name };
    if (permission) body.permission = permission;

    const res = await request(RESEND_API_KEYS_BASE, {
      method: "POST",
      headers: authHeaders(ctx.token),
      body: JSON.stringify(body),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };

    const data = (await res.json()) as ResendCreateApiKeyResponse;
    if (!data.id || !data.token) {
      return {
        ok: false,
        error: makeError(
          "provider_error",
          "resend create: missing id or token in response",
          RESEND_PROVIDER,
          { retryable: false },
        ),
      };
    }

    return {
      ok: true,
      data: {
        id: data.id,
        provider: RESEND_PROVIDER,
        value: data.token,
        metadata: metadataFor({
          key_id: data.id,
          name,
          permission,
        }),
        createdAt: new Date().toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    try {
      await verifyResendAuth({ kind: "env", varName: "RESEND_API_KEY", token: secret.value });
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
    const res = await request(`${RESEND_API_KEYS_BASE}/${keyId}`, {
      method: "DELETE",
      headers: authHeaders(ctx.token),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (res.status === 404) return { ok: true, data: undefined };
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },

  async list(_filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const res = await request(RESEND_API_KEYS_BASE, {
      headers: authHeaders(ctx.token),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "list") };

    const body = (await res.json()) as ResendListApiKeysResponse;
    return {
      ok: true,
      data: (body.data ?? []).flatMap((key) => {
        if (!key.id) return [];
        return [
          {
            id: key.id,
            provider: RESEND_PROVIDER,
            value: "<redacted>",
            metadata: metadataFor({
              key_id: key.id,
              name: key.name,
              last_used_at: key.last_used_at ?? undefined,
            }),
            createdAt: key.created_at ?? new Date(0).toISOString(),
          },
        ];
      }),
    };
  },

  async preloadOwnership(ctx: AuthContext): Promise<OwnershipPreload> {
    const res = await request(RESEND_DOMAINS_BASE, {
      headers: authHeaders(ctx.token),
    });
    if (res instanceof Error) {
      return ownershipPreload([], [], "network_error");
    }
    if (res.status === 401 || res.status === 403) {
      throw fromResponse(res, "preload ownership");
    }
    if (res.status === 429) {
      return ownershipPreload([], [], "rate_limited");
    }
    if (res.status >= 500) {
      return ownershipPreload([], [], "provider_unavailable");
    }
    if (!res.ok) {
      return ownershipPreload([], [], "provider_error");
    }

    try {
      const body = (await res.json()) as ResendListDomainsResponse;
      return ownershipPreload(domainIds(body), domainNames(body));
    } catch {
      return ownershipPreload([], [], "malformed_response");
    }
  },

  async ownedBy(
    secretValue: string,
    _ctx: AuthContext,
    opts?: OwnershipOptions,
  ): Promise<OwnershipResult> {
    const sibling = siblingOwnership(opts);
    const knownDomainIds = knownDomainIdSet(opts?.preload);

    const res = await request(RESEND_DOMAINS_BASE, {
      headers: authHeaders(secretValue),
    });
    if (res instanceof Error) {
      return unknownOwnership("network error while reading Resend domains");
    }
    if (res.status === 401) {
      return unknownOwnership("candidate key cannot read Resend domains");
    }
    if (res.status === 403) {
      return sibling
        ? siblingOwnershipResult(
            sibling,
            "candidate key is send-only; ownership inferred from sibling env vars",
          )
        : unknownOwnership("candidate key is send-only and cannot read Resend domains");
    }
    if (res.status === 429) {
      return unknownOwnership("Resend rate limited the ownership check");
    }
    if (res.status >= 500) {
      return unknownOwnership("provider unavailable");
    }
    if (!res.ok) {
      return unknownOwnership(`Resend domains endpoint returned ${res.status}`);
    }

    let body: ResendListDomainsResponse;
    try {
      body = (await res.json()) as ResendListDomainsResponse;
    } catch {
      return unknownOwnership("Resend domains response was malformed");
    }

    const candidateDomainIds = domainIds(body);
    if (candidateDomainIds.length === 0) {
      return sibling
        ? siblingOwnershipResult(
            sibling,
            "candidate key has no domain fingerprint; ownership inferred from sibling env vars",
          )
        : unknownOwnership("candidate key has no Resend domain fingerprint");
    }
    if (knownDomainIds.size === 0) {
      return sibling
        ? siblingOwnershipResult(
            sibling,
            "admin domain fingerprint unavailable; ownership inferred from sibling env vars",
          )
        : unknownOwnership("admin Resend domain fingerprint unavailable");
    }

    const allKnown = candidateDomainIds.every((id) => knownDomainIds.has(id));
    if (allKnown) {
      return {
        verdict: "self",
        adminCanBill: true,
        scope: "team",
        confidence: "medium",
        evidence: `candidate Resend domains all match the admin fingerprint (${candidateDomainIds.length} domain${candidateDomainIds.length === 1 ? "" : "s"})`,
        strategy: "list-match",
      };
    }

    const someKnown = candidateDomainIds.some((id) => knownDomainIds.has(id));
    if (someKnown) {
      return unknownOwnership("candidate Resend domains partially overlap the admin fingerprint");
    }

    return {
      verdict: "other",
      adminCanBill: false,
      scope: "team",
      confidence: "medium",
      evidence: "candidate Resend domains do not match the admin fingerprint",
      strategy: "list-match",
    };
  },
};

export default resendAdapter;

function authHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
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

function apiKeyName(spec: RotationSpec): string {
  const name = spec.metadata.name || `rotate-cli-${spec.secretId}-${Date.now()}`;
  return name.slice(0, 50);
}

function metadataFor(input: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(input).filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
}

function ownershipPreload(
  knownDomainIds: string[],
  knownDomainNames: string[],
  error?: string,
): OwnershipPreload {
  return {
    knownDomainIds,
    knownDomainNames,
    ...(error ? { error } : {}),
  };
}

function knownDomainIdSet(preload?: OwnershipPreload): Set<string> {
  const value = preload?.knownDomainIds;
  if (value instanceof Set)
    return new Set([...value].filter((id): id is string => typeof id === "string"));
  if (!Array.isArray(value)) return new Set();
  return new Set(value.filter((id): id is string => typeof id === "string"));
}

function domainIds(body: ResendListDomainsResponse): string[] {
  return (body.data ?? []).flatMap((domain) => (domain.id ? [domain.id] : []));
}

function domainNames(body: ResendListDomainsResponse): string[] {
  return (body.data ?? []).flatMap((domain) => (domain.name ? [domain.name] : []));
}

function siblingOwnership(opts?: OwnershipOptions): "self" | "other" | undefined {
  const value = opts?.preload?.vercelSiblingOwnership ?? opts?.preload?.siblingOwnership;
  return value === "self" || value === "other" ? value : undefined;
}

function siblingOwnershipResult(verdict: "self" | "other", evidence: string): OwnershipResult {
  return {
    verdict,
    adminCanBill: verdict === "self",
    scope: "team",
    confidence: "low",
    evidence,
    strategy: "sibling-inheritance",
  };
}

function unknownOwnership(evidence: string): OwnershipResult {
  return {
    verdict: "unknown",
    adminCanBill: false,
    scope: "team",
    confidence: "low",
    evidence,
    strategy: "list-match",
  };
}

function networkError(cause: Error) {
  return makeError("network_error", `resend network error: ${cause.message}`, RESEND_PROVIDER, {
    cause,
  });
}

function fromResponse(res: Response, op: string) {
  return fromStatus(res.status, op);
}

function fromStatus(status: number, op: string) {
  if (status === 401 || status === 403) {
    return makeError("auth_failed", `resend ${op}: ${status}`, RESEND_PROVIDER);
  }
  if (status === 429) return makeError("rate_limited", `resend ${op}: 429`, RESEND_PROVIDER);
  if (status === 404) return makeError("not_found", `resend ${op}: 404`, RESEND_PROVIDER);
  if (status >= 500) {
    return makeError("provider_error", `resend ${op}: ${status}`, RESEND_PROVIDER);
  }
  return makeError("provider_error", `resend ${op}: ${status}`, RESEND_PROVIDER, {
    retryable: false,
  });
}
