import { makeError, resolveRegisteredAuth } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  OwnershipResult,
  PromptIO,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";
import { firecrawlAuthDefinition } from "./auth.ts";

const FIRECRAWL_BASE = process.env.FIRECRAWL_API_URL ?? "https://api.firecrawl.dev";
const PROVIDER = "firecrawl";

export const adapterFirecrawlAdapter: Adapter = {
  name: PROVIDER,
  authRef: PROVIDER,
  authDefinition: firecrawlAuthDefinition,
  mode: "manual-assist",

  async auth(): Promise<AuthContext> {
    return resolveRegisteredAuth(PROVIDER);
  },

  async create(spec: RotationSpec, _ctx: AuthContext): Promise<RotationResult<Secret>> {
    const io = spec.io;
    if (!io?.isInteractive) return unsupported("Firecrawl create requires interactive IO");

    io.note(createInstructions());
    const value = (await io.promptSecret("Paste the new FIRECRAWL_API_KEY")).trim();
    if (!value) {
      return {
        ok: false,
        error: makeError("invalid_spec", "pasted FIRECRAWL_API_KEY was empty", PROVIDER),
      };
    }

    return {
      ok: true,
      data: {
        id: spec.secretId,
        provider: PROVIDER,
        value,
        metadata: { ...spec.metadata, manual_assist: "true" },
        createdAt: new Date().toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    const res = await request(`${FIRECRAWL_BASE}/v2/team/credit-usage`, {
      headers: authHeaders(secret.value),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(
    secret: Secret,
    _ctx: AuthContext,
    opts?: { io?: PromptIO },
  ): Promise<RotationResult<void>> {
    const io = opts?.io;
    if (!io?.isInteractive) return unsupported("Firecrawl revoke requires interactive IO");

    io.note(revokeInstructions(secret));
    const confirmed = await io.confirm("Confirm the old Firecrawl API key has been revoked", {
      initialValue: false,
    });
    if (!confirmed) {
      return {
        ok: false,
        error: makeError("unsupported", "Firecrawl revoke was not confirmed", PROVIDER),
      };
    }
    return { ok: true, data: undefined };
  },

  async ownedBy(_value: string, _ctx: AuthContext): Promise<OwnershipResult> {
    return unknownOwnership(
      "Firecrawl has no documented API key introspection or ownership endpoint; a valid key proves liveness only.",
    );
  },
};

export default adapterFirecrawlAdapter;

function createInstructions(): string {
  return [
    "Firecrawl API key rotation is manual-assist because Firecrawl does not document public API key create, list, delete, or introspection endpoints.",
    "Open https://www.firecrawl.dev/app/api-keys.",
    "Create a replacement API key for the same Firecrawl team or workspace.",
    "Copy the key immediately; Firecrawl dashboard key creation may reveal the secret only once.",
    "Paste only the replacement FIRECRAWL_API_KEY when prompted.",
  ].join("\n");
}

function revokeInstructions(secret: Secret): string {
  return [
    "Firecrawl old API key cleanup is manual-assist.",
    "Open https://www.firecrawl.dev/app/api-keys.",
    `Target secret id: ${secret.id}`,
    "Find and revoke the old API key in the Firecrawl dashboard.",
    "Confirm only after the old key is no longer active.",
  ].join("\n");
}

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

function networkError(cause: Error) {
  return makeError("network_error", `firecrawl network error: ${cause.message}`, PROVIDER, {
    cause,
  });
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `firecrawl ${op}: ${res.status}`, PROVIDER);
  }
  if (res.status === 429) return makeError("rate_limited", `firecrawl ${op}: 429`, PROVIDER);
  if (res.status >= 500) {
    return makeError("provider_error", `firecrawl ${op}: ${res.status}`, PROVIDER);
  }
  return makeError("provider_error", `firecrawl ${op}: ${res.status}`, PROVIDER, {
    retryable: false,
  });
}

function unsupported(message: string): RotationResult<never> {
  return {
    ok: false,
    error: makeError("unsupported", message, PROVIDER, { retryable: false }),
  };
}

function unknownOwnership(evidence: string): OwnershipResult {
  return {
    verdict: "unknown",
    adminCanBill: false,
    confidence: "low",
    evidence,
    strategy: "api-introspection",
  };
}
