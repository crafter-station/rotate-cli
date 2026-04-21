import { makeError } from "@rotate/core";
import { resolveRegisteredAuth } from "@rotate/core/auth";
import type {
  Adapter,
  AuthContext,
  OwnershipOptions,
  OwnershipResult,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";
import { clerkAuthDefinition } from "./auth.ts";

const PLAPI_BASE = process.env.CLERK_PLAPI_URL ?? "https://api.clerk.com";

const PUBLISHABLE_KEY_NAMES = [
  "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
  "CLERK_PUBLISHABLE_KEY",
  "VITE_CLERK_PUBLISHABLE_KEY",
  "NUXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
];

export interface ClerkApiKey {
  id: string;
  secret: string;
  instance_id: string;
  created_at: number;
}

export const clerkAdapter: Adapter = {
  name: "clerk",
  authRef: "clerk",
  authDefinition: clerkAuthDefinition,

  async auth(): Promise<AuthContext> {
    return resolveRegisteredAuth("clerk");
  },

  async preloadOwnership(ctx: AuthContext) {
    // Enumerate the Clerk instances the auth token can see, and for each
    // pull the FAPI host + JWKS key ids. These two sets are what ownedBy()
    // checks against to decide self/other.
    //
    // PLAPI endpoint: GET /v1/instances lists every instance the caller owns.
    // We intentionally fan out in parallel — for a typical Clerk account
    // (1-5 instances) this is <1s, and the preload is only computed once
    // per `who` invocation anyway.
    const knownFapiHosts = new Set<string>();
    const knownKids = new Set<string>();
    try {
      const res = await fetch(`${PLAPI_BASE}/v1/instances`, {
        headers: { Authorization: `Bearer ${ctx.token}` },
      });
      if (!res.ok) return { knownFapiHosts, knownKids };
      const body = (await res.json()) as Array<{
        id: string;
        home_origin?: string;
        frontend_api_url?: string;
        development?: boolean;
      }>;
      const instances = Array.isArray(body) ? body : [];
      // For each instance: extract fapi_host from frontend_api_url, fetch
      // JWKS to learn its kids. JWKS is public — no auth needed.
      await Promise.all(
        instances.map(async (inst) => {
          if (inst.frontend_api_url) {
            try {
              const u = new URL(inst.frontend_api_url);
              knownFapiHosts.add(u.host.toLowerCase());
            } catch {
              /* ignore malformed URL */
            }
          }
          // JWKS lives at `<frontend_api_url>/.well-known/jwks.json`
          if (inst.frontend_api_url) {
            try {
              const jwksRes = await fetch(
                `${inst.frontend_api_url.replace(/\/$/, "")}/.well-known/jwks.json`,
              );
              if (jwksRes.ok) {
                const jwks = (await jwksRes.json()) as { keys?: Array<{ kid?: string }> };
                for (const k of jwks.keys ?? []) {
                  if (typeof k.kid === "string") knownKids.add(k.kid);
                }
              }
            } catch {
              /* ignore network failure */
            }
          }
        }),
      );
      return { knownFapiHosts, knownKids };
    } catch {
      return { knownFapiHosts, knownKids };
    }
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const instanceId = spec.metadata.instance_id;
    if (!instanceId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.instance_id is required", "clerk"),
      };
    }
    const res = await fetch(`${PLAPI_BASE}/v1/instances/${instanceId}/api_keys`, {
      method: "POST",
      headers: authHeaders(ctx),
      body: JSON.stringify({ name: `rotate-cli-${Date.now()}` }),
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };
    const data = (await res.json()) as ClerkApiKey;
    return {
      ok: true,
      data: {
        id: data.id,
        provider: "clerk",
        value: data.secret,
        metadata: { instance_id: data.instance_id, key_id: data.id },
        createdAt: new Date((data.created_at ?? Date.now()) * 1000).toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    // Verify the NEW key by calling /v1/me with it as bearer.
    const res = await fetch(`${PLAPI_BASE}/v1/me`, {
      headers: { Authorization: `Bearer ${secret.value}` },
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
    const instanceId = secret.metadata.instance_id;
    const keyId = secret.metadata.key_id ?? secret.id;
    if (!instanceId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.instance_id missing", "clerk"),
      };
    }
    const res = await fetch(`${PLAPI_BASE}/v1/instances/${instanceId}/api_keys/${keyId}`, {
      method: "DELETE",
      headers: authHeaders(ctx),
    });
    if (res.status === 404) return { ok: true, data: undefined }; // idempotent
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },

  async list(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const instanceId = filter.instance_id;
    if (!instanceId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "filter.instance_id required", "clerk"),
      };
    }
    const res = await fetch(`${PLAPI_BASE}/v1/instances/${instanceId}/api_keys`, {
      headers: authHeaders(ctx),
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "list") };
    const data = (await res.json()) as ClerkApiKey[];
    return {
      ok: true,
      data: data.map((k) => ({
        id: k.id,
        provider: "clerk",
        value: "<redacted>",
        metadata: { instance_id: k.instance_id, key_id: k.id },
        createdAt: new Date((k.created_at ?? 0) * 1000).toISOString(),
      })),
    };
  },

  async ownedBy(
    secretValue: string,
    _ctx: AuthContext,
    opts?: OwnershipOptions,
  ): Promise<OwnershipResult> {
    const secret = cleanValue(secretValue);

    if (secret.startsWith("whsec_")) {
      const sibling = cleanValue(opts?.coLocatedVars?.CLERK_SECRET_KEY);
      if (!sibling || sibling === secret) {
        return unknownOwnership(
          "webhook secret has no owner-identifying content and no sibling Clerk secret was provided",
          "sibling-inheritance",
        );
      }

      const inherited = await clerkAdapter.ownedBy?.(sibling, _ctx, opts);
      if (!inherited || inherited.verdict === "unknown") {
        return unknownOwnership(
          "webhook secret has no owner-identifying content and sibling Clerk secret ownership is unknown",
          "sibling-inheritance",
        );
      }

      return {
        verdict: inherited.verdict,
        adminCanBill: inherited.adminCanBill,
        scope: inherited.scope,
        teamRole: inherited.teamRole,
        confidence: inherited.verdict === "self" ? "medium" : inherited.confidence,
        evidence: `webhook secret inherits sibling Clerk secret ownership: ${inherited.evidence}`,
        strategy: "sibling-inheritance",
      };
    }

    const publishableKey = findPublishableKey(secret, opts?.coLocatedVars);
    if (publishableKey) {
      const decoded = decodeFapi(publishableKey);
      if (!decoded) {
        return unknownOwnership("co-located Clerk publishable key could not be decoded");
      }

      const secretEnv = clerkKeyEnvironment(secret);
      if (secretEnv && decoded.environment !== secretEnv) {
        return {
          verdict: "unknown",
          adminCanBill: false,
          scope: "project",
          confidence: "medium",
          evidence: "Clerk secret key environment does not match co-located publishable key",
          strategy: "format-decode",
        };
      }

      const knownHosts = stringSetFromPreload(opts?.preload, [
        "knownFapiHosts",
        "clerkKnownFapiHosts",
        "fapiHosts",
      ]);

      if (knownHosts.size > 0) {
        if (knownHosts.has(decoded.host)) {
          return {
            verdict: "self",
            adminCanBill: true,
            scope: "project",
            confidence: "high",
            evidence: `decoded Clerk publishable key host matches known FAPI host ${decoded.host}`,
            strategy: "format-decode",
          };
        }
        return {
          verdict: "other",
          adminCanBill: false,
          scope: "project",
          confidence: "high",
          evidence: `decoded Clerk publishable key host ${decoded.host} is not in known FAPI hosts`,
          strategy: "format-decode",
        };
      }

      return unknownOwnership(
        `decoded Clerk publishable key host ${decoded.host}, but PLAPI preload unavailable — set a valid CLERK_PLAPI_TOKEN and retry`,
      );
    }

    if (!secret.startsWith("sk_")) {
      return unknownOwnership("secret is not a Clerk secret key or webhook secret");
    }

    const knownKids = stringSetFromPreload(opts?.preload, ["knownKids", "clerkKnownKids"]);
    if (knownKids.size === 0) {
      return unknownOwnership(
        "no Clerk publishable key sibling or known JWKS key fingerprints available",
      );
    }

    try {
      const res = await fetch(`${PLAPI_BASE}/v1/jwks`, {
        headers: { Authorization: `Bearer ${secret}` },
      });

      if (res.status === 401 || res.status === 403) {
        return unknownOwnership("Clerk JWKS introspection was not authorized", "api-introspection");
      }
      if (res.status === 429) {
        return unknownOwnership("Clerk ownership check was rate limited", "api-introspection");
      }
      if (res.status >= 500) {
        return unknownOwnership("provider unavailable", "api-introspection");
      }
      if (!res.ok) {
        return unknownOwnership(
          `Clerk JWKS introspection returned ${res.status}`,
          "api-introspection",
        );
      }

      const jwks = (await res.json()) as { keys?: Array<{ kid?: string }> };
      const kids = (jwks.keys ?? [])
        .map((key) => key.kid)
        .filter((kid): kid is string => Boolean(kid));
      if (kids.length === 0) {
        return unknownOwnership(
          "Clerk JWKS response did not include key fingerprints",
          "api-introspection",
        );
      }

      if (kids.some((kid) => knownKids.has(kid))) {
        return {
          verdict: "self",
          adminCanBill: true,
          scope: "project",
          confidence: "medium",
          evidence: "Clerk JWKS key fingerprint matches known instance fingerprint",
          strategy: "api-introspection",
        };
      }

      return {
        verdict: "other",
        adminCanBill: false,
        scope: "project",
        confidence: "medium",
        evidence: "Clerk JWKS key fingerprints do not match known instance fingerprints",
        strategy: "api-introspection",
      };
    } catch {
      return unknownOwnership("provider unavailable", "api-introspection");
    }
  },
};

export default clerkAdapter;

function authHeaders(ctx: AuthContext): Record<string, string> {
  return {
    Authorization: `Bearer ${ctx.token}`,
    "Content-Type": "application/json",
  };
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `clerk ${op}: ${res.status}`, "clerk");
  }
  if (res.status === 429) return makeError("rate_limited", `clerk ${op}: 429`, "clerk");
  if (res.status === 404) return makeError("not_found", `clerk ${op}: 404`, "clerk");
  if (res.status >= 500) {
    return makeError("provider_error", `clerk ${op}: ${res.status}`, "clerk");
  }
  return makeError("provider_error", `clerk ${op}: ${res.status}`, "clerk", {
    retryable: false,
  });
}

function findPublishableKey(
  secretValue: string,
  coLocatedVars: Record<string, string> | undefined,
): string | undefined {
  if (secretValue.startsWith("pk_")) return secretValue;
  for (const name of PUBLISHABLE_KEY_NAMES) {
    const value = cleanValue(coLocatedVars?.[name]);
    if (value.startsWith("pk_")) return value;
  }
  return undefined;
}

function decodeFapi(pk: string): { host: string; environment: "live" | "test" } | undefined {
  const match = cleanValue(pk).match(/^pk_(live|test)_(.+)$/);
  if (!match) return undefined;
  const [, environment, encoded] = match as [string, "live" | "test", string];

  try {
    const body = encoded.replace(/-/g, "+").replace(/_/g, "/");
    const decoded = Buffer.from(body, "base64").toString("utf8");
    const host = decoded.replace(/\$$/, "").toLowerCase();
    if (!host || host.includes("/") || /\s/.test(host)) return undefined;
    return { host, environment };
  } catch {
    return undefined;
  }
}

function clerkKeyEnvironment(value: string): "live" | "test" | undefined {
  const match = cleanValue(value).match(/^(?:sk|pk)_(live|test)_/);
  return match?.[1] as "live" | "test" | undefined;
}

function stringSetFromPreload(
  preload: Record<string, unknown> | undefined,
  keys: string[],
): Set<string> {
  const values = new Set<string>();
  for (const key of keys) {
    const value = preload?.[key];
    if (value instanceof Set) {
      for (const item of value) {
        if (typeof item === "string") values.add(item.toLowerCase());
      }
    } else if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === "string") values.add(item.toLowerCase());
      }
    }
  }
  return values;
}

function cleanValue(value: string | undefined): string {
  const trimmed = (value ?? "").trim();
  const quote = trimmed[0];
  if ((quote === '"' || quote === "'") && trimmed.endsWith(quote)) {
    return trimmed.slice(1, -1).trim();
  }
  return trimmed;
}

function unknownOwnership(
  evidence: string,
  strategy: OwnershipResult["strategy"] = "format-decode",
): OwnershipResult {
  return {
    verdict: "unknown",
    adminCanBill: false,
    confidence: "low",
    evidence,
    strategy,
  };
}
