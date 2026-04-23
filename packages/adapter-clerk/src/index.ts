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
  // Clerk does not expose a supported BAPI/PLAPI endpoint to create
  // additional instance Secret Keys programmatically. The dashboard flow
  // at /~/api-keys is the only path. So we go manual-assist: open the
  // browser at the right instance, ask the user to paste the new key,
  // and propagate automatically to every vercel-env consumer.
  //
  // Preload + ownedBy stay online: they use PLAPI to enumerate apps
  // for fingerprinting, which is fully supported.
  mode: "manual-assist",

  async auth(): Promise<AuthContext> {
    return resolveRegisteredAuth("clerk");
  },

  async preloadOwnership(ctx: AuthContext) {
    // Enumerate the Clerk applications the Platform API token can see via
    // GET /v1/platform/applications (needs a Platform API access token —
    // `ak_...` or `plapi_...` — NOT a secret key or BAPI key).
    //
    // Each application has `instances[]` with a `publishable_key` (pk_live_*
    // or pk_test_*). Decoding the base64 after the prefix yields the FAPI
    // host (e.g. `fine-bunny-57.clerk.accounts.dev` for dev, or
    // `clerk.myapp.com` for production). Those are the hosts ownedBy()
    // compares against.
    //
    // Throws on 401/403 so preloadOwnershipForSecrets shows preload-failed
    // instead of silently returning empty sets (which would mask the auth
    // issue as 95 useless "unknown" verdicts).
    const knownFapiHosts = new Set<string>();
    const knownKids = new Set<string>();
    // host → { instance_id, app_id, environment_type } so manual-assist
    // create() can build a deep-link to the right dashboard page AND so
    // revoke() knows which app to point the user at.
    const hostToInstance = new Map<
      string,
      { instanceId: string; appId?: string; environment?: string }
    >();

    const res = await fetch(`${PLAPI_BASE}/v1/platform/applications`, {
      headers: { Authorization: `Bearer ${ctx.token}` },
    });
    if (res.status === 401 || res.status === 403) {
      const body = await res.text();
      throw new Error(
        `Clerk PLAPI rejected token (${res.status}). Need a Platform API access token (ak_... or plapi_...) from dashboard.clerk.com → Settings → API keys → Platform API. ${body.slice(0, 120)}`,
      );
    }
    if (!res.ok) return { knownFapiHosts, knownKids, hostToInstance };

    const apps = (await res.json()) as Array<{
      application_id?: string;
      name?: string;
      instances?: Array<{
        instance_id?: string;
        environment_type?: string;
        publishable_key?: string;
      }>;
    }>;

    // Collect all publishable keys so we can decode their FAPI hosts. The
    // JWKS fetch per-instance is public (no auth) — do it in parallel so
    // large accounts preload in <2s.
    const pkList: Array<{ pk: string; host: string }> = [];
    for (const app of Array.isArray(apps) ? apps : []) {
      for (const inst of app.instances ?? []) {
        const pk = inst.publishable_key;
        if (!pk) continue;
        const decoded = decodeFapi(pk);
        if (decoded) {
          knownFapiHosts.add(decoded.host);
          pkList.push({ pk, host: decoded.host });
          if (inst.instance_id) {
            hostToInstance.set(decoded.host, {
              instanceId: inst.instance_id,
              appId: app.application_id,
              environment: inst.environment_type,
            });
          }
        }
      }
    }

    // Fetch JWKS per unique host in parallel. JWKS gives us `kid` fingerprints
    // which are the secondary way ownedBy() confirms self-ownership when the
    // sibling publishable key isn't co-located.
    const uniqueHosts = [...new Set(pkList.map((p) => `https://${p.host}/.well-known/jwks.json`))];
    await Promise.all(
      uniqueHosts.map(async (url) => {
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), 5_000);
        try {
          const jwksRes = await fetch(url, { signal: ctrl.signal });
          if (!jwksRes.ok) return;
          const jwks = (await jwksRes.json()) as { keys?: Array<{ kid?: string }> };
          for (const k of jwks.keys ?? []) {
            if (typeof k.kid === "string") knownKids.add(k.kid);
          }
        } catch {
          /* ignore per-host failure — partial index still useful */
        } finally {
          clearTimeout(tid);
        }
      }),
    );

    return { knownFapiHosts, knownKids, hostToInstance };
  },

  async create(spec: RotationSpec, _ctx: AuthContext): Promise<RotationResult<Secret>> {
    const io = spec.io;
    if (!io?.isInteractive) {
      return {
        ok: false,
        error: makeError(
          "unsupported",
          "Clerk rotation is manual-assist — re-run with --manual-only from an interactive TTY so you can paste the new key",
          "clerk",
          { retryable: false },
        ),
      };
    }
    const location = resolveInstanceLocation(spec);
    const dashboardUrl = buildDashboardUrl(location);
    const envLabel = location?.environment ? `${location.environment} ` : "";
    io.note(
      [
        "Clerk Secret Key rotation is manual-assist: Clerk does not expose a supported API to",
        "programmatically create additional instance Secret Keys. The dashboard flow is the only path.",
        "",
        `Open: ${dashboardUrl}`,
        `Target: ${spec.secretId} (${envLabel}instance)`,
        "",
        "Steps:",
        `1. In the Clerk Dashboard, open the app above → API keys → + Add new key.`,
        `2. Name the new key e.g. "rotate-cli-${Date.now().toString(36)}".`,
        "3. Copy the new Secret Key value (sk_live_* / sk_test_*).",
        "4. Paste it below. rotate-cli will propagate it to every vercel-env consumer automatically.",
        "5. Leave the OLD key alive during the grace period — rotate will prompt you to delete it",
        "   from the dashboard after consumers sync.",
      ].join("\n"),
    );
    const value = (await io.promptSecret("Paste the new Clerk Secret Key")).trim();
    if (!value) {
      return {
        ok: false,
        error: makeError("invalid_spec", "pasted Clerk Secret Key was empty", "clerk"),
      };
    }
    if (!/^sk_(live|test)_/.test(value)) {
      return {
        ok: false,
        error: makeError(
          "invalid_spec",
          "pasted value does not look like a Clerk Secret Key (expected sk_live_* or sk_test_*)",
          "clerk",
        ),
      };
    }
    return {
      ok: true,
      data: {
        id: spec.secretId,
        provider: "clerk",
        value,
        metadata: {
          ...spec.metadata,
          manual_assist: "true",
          ...(location?.instanceId ? { instance_id: location.instanceId } : {}),
          ...(location?.appId ? { app_id: location.appId } : {}),
          ...(location?.environment ? { environment: location.environment } : {}),
        },
        createdAt: new Date().toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    // The new key is a BAPI secret key — /v1/me doesn't accept it (404).
    // Use /v1/jwks instead which every BAPI key can fetch. That proves
    // the pasted value is at least a live Clerk Secret Key pointing at
    // some instance's FAPI.
    const res = await fetch(`${PLAPI_BASE}/v1/jwks`, {
      headers: { Authorization: `Bearer ${secret.value}` },
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
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
          "Clerk revoke is manual-assist — re-run with --manual-only from a TTY to confirm deletion",
          "clerk",
          { retryable: false },
        ),
      };
    }
    const appId = secret.metadata.app_id;
    const instanceId = secret.metadata.instance_id;
    const environment = secret.metadata.environment;
    const dashboardUrl = buildDashboardUrl(
      appId && instanceId ? { appId, instanceId, environment } : undefined,
    );
    io.note(
      [
        "Clerk old key cleanup is manual-assist.",
        "",
        `Open: ${dashboardUrl}`,
        `Target: ${secret.id}`,
        "",
        "Under Secret Keys, find the OLD key (not the one you just added) and delete it.",
        "Clerk warns you if the key was used recently — check the Last used timestamp first.",
        "Confirm only after the old key is gone.",
      ].join("\n"),
    );
    const confirmed = await io.confirm("Confirm the old Clerk Secret Key has been deleted", {
      initialValue: false,
    });
    if (!confirmed) {
      return {
        ok: false,
        error: makeError("unsupported", "Clerk revoke was not confirmed", "clerk"),
      };
    }
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
        // sk_ doesn't authenticate against any of our instances — strong
        // signal it belongs to another Clerk account. Medium confidence
        // catches the edge where the sk_ is expired (rotated by someone)
        // but was ours originally.
        return {
          verdict: "other",
          adminCanBill: false,
          scope: "project",
          confidence: "medium",
          evidence: `Clerk secret key was rejected by PLAPI (${res.status}) — not associated with any instance visible to the authenticated admin`,
          strategy: "api-introspection",
        };
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

interface ClerkLocation {
  instanceId: string;
  appId?: string;
  environment?: string;
}

/**
 * Auto-resolve the Clerk dashboard location (app_id + instance_id) from the
 * rotation spec's context. Uses the co-located CLERK_PUBLISHABLE_KEY to
 * decode the FAPI host, then looks it up in the preload's hostToInstance
 * map built by preloadOwnership(). Returns undefined when either is
 * missing — the caller falls back to the generic `/~/api-keys` link.
 */
function resolveInstanceLocation(spec: RotationSpec): ClerkLocation | undefined {
  const pk = findPublishableKey(spec.currentValue ?? "", spec.coLocatedVars);
  if (!pk) return undefined;
  const decoded = decodeFapi(pk);
  if (!decoded) return undefined;
  const map = spec.preload?.hostToInstance;
  const get = (key: string): unknown =>
    map instanceof Map
      ? map.get(key)
      : map && typeof map === "object"
        ? (map as Record<string, unknown>)[key]
        : undefined;
  const raw = get(decoded.host);
  // Back-compat: earlier preload shape stored just the instance_id string.
  if (typeof raw === "string") return { instanceId: raw };
  if (raw && typeof raw === "object") {
    const obj = raw as { instanceId?: string; appId?: string; environment?: string };
    if (obj.instanceId)
      return { instanceId: obj.instanceId, appId: obj.appId, environment: obj.environment };
  }
  return undefined;
}

/**
 * Build the Clerk dashboard URL the user should open. When we know both
 * app_id and instance_id, deep-link straight to the api-keys page for that
 * environment. Otherwise fall back to the app-wide "last-active" shortcut.
 */
function buildDashboardUrl(location: ClerkLocation | undefined): string {
  if (location?.appId && location.instanceId) {
    return `https://dashboard.clerk.com/apps/${location.appId}/instances/${location.instanceId}/api-keys`;
  }
  return "https://dashboard.clerk.com/~/api-keys";
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
