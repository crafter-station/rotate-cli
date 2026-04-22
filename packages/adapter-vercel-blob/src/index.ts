import { makeError, resolveRegisteredAuth } from "@rotate/core";
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
import { vercelBlobAuthDefinition } from "./auth.ts";

const VERCEL_BASE = process.env.VERCEL_API_URL ?? "https://api.vercel.com";
const PROVIDER = "vercel-blob";

interface BlobStore {
  id?: string;
  name?: string;
  type?: string;
  region?: string;
  access?: string;
  projectsMetadata?: Array<{ projectId?: string; name?: string; environments?: string[] }>;
}

interface StoreResponse {
  store?: BlobStore;
}

interface StoresResponse {
  stores?: BlobStore[];
}

interface TeamsResponse {
  teams?: Array<{ id?: string }>;
}

interface VercelBlobPreload extends OwnershipPreload {
  stores?: BlobStore[];
  complete?: boolean;
}

export const adapterVercelBlobAdapter: Adapter = {
  name: PROVIDER,
  authRef: PROVIDER,
  authDefinition: vercelBlobAuthDefinition,
  mode: "manual-assist",

  async auth(): Promise<AuthContext> {
    return resolveRegisteredAuth(PROVIDER);
  },

  async create(spec: RotationSpec, _ctx: AuthContext): Promise<RotationResult<Secret>> {
    const io = spec.io;
    if (!io?.isInteractive) return unsupported("create requires interactive manual-assist IO");

    io.note(createInstructions(spec.metadata));
    const value = (await io.promptSecret("Paste the new BLOB_READ_WRITE_TOKEN")).trim();
    if (!value) {
      return {
        ok: false,
        error: makeError("invalid_spec", "pasted BLOB_READ_WRITE_TOKEN was empty", PROVIDER),
      };
    }

    const storeId = deriveStoreId(value) ?? metadataStoreId(spec.metadata);
    return {
      ok: true,
      data: {
        id: storeId ?? spec.secretId,
        provider: PROVIDER,
        value,
        metadata: metadataFor({
          ...spec.metadata,
          ...(storeId ? { store_id: storeId } : {}),
          manual_assist: "true",
        }),
        createdAt: new Date().toISOString(),
      },
    };
  },

  async verify(secret: Secret, ctx: AuthContext): Promise<RotationResult<boolean>> {
    const storeId = deriveStoreId(secret.value) ?? metadataStoreId(secret.metadata);
    if (!storeId) {
      return {
        ok: false,
        error: makeError(
          "invalid_spec",
          "cannot verify Vercel Blob token without token-derived or metadata store_id",
          PROVIDER,
          { retryable: false },
        ),
      };
    }

    const res = await request(storeUrl(storeId, secret.metadata), {
      headers: authHeaders(ctx),
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
    if (!io?.isInteractive) return unsupported("revoke requires interactive manual-assist IO");

    io.note(revokeInstructions(secret));
    const confirmed = await io.confirm(
      "Confirm the old Vercel Blob credential has been removed or invalidated",
      { initialValue: false },
    );
    if (!confirmed) {
      return {
        ok: false,
        error: makeError("unsupported", "Vercel Blob revoke was not confirmed", PROVIDER, {
          retryable: false,
        }),
      };
    }
    return { ok: true, data: undefined };
  },

  async preloadOwnership(ctx: AuthContext): Promise<OwnershipPreload> {
    const stores: BlobStore[] = [];
    let complete = true;
    const userStores = await fetchStores(ctx, undefined);
    if (userStores.ok) stores.push(...userStores.stores);
    else complete = false;

    const teams = await fetchTeams(ctx);
    if (teams.ok) {
      for (const teamId of teams.teamIds) {
        const teamStores = await fetchStores(ctx, { teamId });
        if (teamStores.ok) stores.push(...teamStores.stores);
        else complete = false;
      }
    } else {
      complete = false;
    }

    return {
      stores: dedupeStores(stores),
      complete,
    };
  },

  async ownedBy(
    value: string,
    ctx: AuthContext,
    opts?: OwnershipOptions,
  ): Promise<OwnershipResult> {
    const storeId = deriveStoreId(value) ?? opts?.coLocatedVars?.BLOB_STORE_ID;
    if (!storeId) {
      return unknownOwnership("no Vercel Blob store id could be derived from token or siblings");
    }

    const res = await request(storeUrl(storeId, opts?.coLocatedVars), {
      headers: authHeaders(ctx),
    });
    if (res instanceof Error) {
      return unknownOwnership("network error while reading Vercel Blob store");
    }
    if (res.status === 404) {
      return ownershipForMissingStore(storeId, opts?.preload);
    }
    if (res.status === 401 || res.status === 403) {
      return unknownOwnership("admin Vercel token cannot read Blob stores");
    }
    if (res.status === 429) {
      return unknownOwnership("Vercel rate limited the ownership check");
    }
    if (res.status >= 500) {
      return unknownOwnership("Vercel storage API unavailable");
    }
    if (!res.ok) {
      return unknownOwnership(`Vercel storage API returned ${res.status}`);
    }

    try {
      const body = (await res.json()) as StoreResponse;
      const store = body.store;
      if (!store?.id) return unknownOwnership("Vercel storage response did not include a store");
      return selfOwnership(store);
    } catch {
      return unknownOwnership("Vercel storage response was malformed");
    }
  },
};

export default adapterVercelBlobAdapter;

function createInstructions(metadata: Record<string, string>): string {
  const currentStore = metadataStoreId(metadata);
  return [
    "Vercel Blob credential rotation is manual-assist because Vercel does not document a credential reset endpoint.",
    "Open https://vercel.com/dashboard/stores/blob and select the target Blob store.",
    currentStore
      ? `Target store id: ${currentStore}`
      : "Use the project env vars to identify the target Blob store.",
    "Create or reveal the replacement BLOB_READ_WRITE_TOKEN in Vercel, preserving the existing store region and access settings.",
    "Paste only the replacement token when prompted.",
  ].join("\n");
}

function revokeInstructions(secret: Secret): string {
  const storeId = metadataStoreId(secret.metadata) ?? deriveStoreId(secret.value) ?? secret.id;
  return [
    "Vercel Blob old credential cleanup is manual-assist.",
    "Open https://vercel.com/dashboard/stores/blob and select the target Blob store.",
    `Target store id: ${storeId}`,
    "Remove, invalidate, or stop using the old BLOB_READ_WRITE_TOKEN in every connected project and downstream consumer.",
    "Confirm only after the old token is no longer active in your deployment surface.",
  ].join("\n");
}

function deriveStoreId(value: string): string | undefined {
  const segment = value.split("_")[3];
  if (!segment) return undefined;
  return segment.startsWith("store_") ? segment : `store_${segment}`;
}

function metadataStoreId(metadata: Record<string, string>): string | undefined {
  return metadata.store_id ?? metadata.storeId ?? metadata.BLOB_STORE_ID;
}

function storeUrl(storeId: string, source?: Record<string, string>): string {
  const url = new URL(`${VERCEL_BASE}/v1/storage/stores/${storeId}`);
  applyAccountParams(url, source);
  return url.toString();
}

function storesUrl(account?: { teamId?: string; accountId?: string }): string {
  const url = new URL(`${VERCEL_BASE}/v1/storage/stores`);
  applyAccountParams(url, account);
  return url.toString();
}

function applyAccountParams(
  url: URL,
  source?: Record<string, string> | { teamId?: string; accountId?: string },
): void {
  if (!source) return;
  const values = source as Record<string, string | undefined>;
  const teamId = values.teamId ?? values.team_id ?? values.VERCEL_TEAM_ID ?? values.TEAM_ID;
  const accountId =
    values.accountId ?? values.account_id ?? values.VERCEL_ACCOUNT_ID ?? values.ACCOUNT_ID;
  if (teamId) url.searchParams.set("teamId", teamId);
  if (accountId) url.searchParams.set("accountId", accountId);
}

async function fetchStores(
  ctx: AuthContext,
  account: { teamId?: string; accountId?: string } | undefined,
): Promise<{ ok: true; stores: BlobStore[] } | { ok: false }> {
  const res = await request(storesUrl(account), { headers: authHeaders(ctx) });
  if (res instanceof Error || !res.ok) return { ok: false };
  try {
    const body = (await res.json()) as StoresResponse;
    return { ok: true, stores: (body.stores ?? []).filter(isBlobStore) };
  } catch {
    return { ok: false };
  }
}

async function fetchTeams(
  ctx: AuthContext,
): Promise<{ ok: true; teamIds: string[] } | { ok: false }> {
  const res = await request(`${VERCEL_BASE}/v2/teams`, { headers: authHeaders(ctx) });
  if (res instanceof Error || !res.ok) return { ok: false };
  try {
    const body = (await res.json()) as TeamsResponse;
    return {
      ok: true,
      teamIds: (body.teams ?? []).flatMap((team) => (team.id ? [team.id] : [])),
    };
  } catch {
    return { ok: false };
  }
}

function isBlobStore(store: BlobStore): boolean {
  return !store.type || store.type === "blob";
}

function dedupeStores(stores: BlobStore[]): BlobStore[] {
  const seen = new Set<string>();
  const result: BlobStore[] = [];
  for (const store of stores) {
    if (!store.id || seen.has(store.id)) continue;
    seen.add(store.id);
    result.push(store);
  }
  return result;
}

function selfOwnership(store: BlobStore): OwnershipResult {
  return {
    verdict: "self",
    adminCanBill: true,
    scope: store.projectsMetadata?.length ? "project" : "team",
    confidence: "medium",
    evidence: `Vercel Blob store ${store.id} is readable with the admin Vercel token`,
    strategy: "format-decode",
  };
}

function ownershipForMissingStore(
  storeId: string,
  preload: OwnershipPreload | undefined,
): OwnershipResult {
  const parsed = parsePreload(preload);
  if (!parsed.complete) {
    return unknownOwnership(
      `Vercel Blob store ${storeId} was not found, but account preload is incomplete`,
    );
  }
  const inPreload = parsed.stores.some((store) => store.id === storeId);
  if (inPreload) {
    return unknownOwnership(
      `Vercel Blob store ${storeId} was found in preload but direct lookup returned 404`,
    );
  }
  return {
    verdict: "other",
    adminCanBill: false,
    scope: "team",
    confidence: "medium",
    evidence: `Vercel Blob store ${storeId} is absent from the complete admin store preload`,
    strategy: "format-decode",
  };
}

function parsePreload(preload: OwnershipPreload | undefined): {
  stores: BlobStore[];
  complete: boolean;
} {
  const candidate = preload as VercelBlobPreload | undefined;
  return {
    stores: Array.isArray(candidate?.stores) ? candidate.stores : [],
    complete: candidate?.complete === true,
  };
}

function unknownOwnership(evidence: string): OwnershipResult {
  return {
    verdict: "unknown",
    adminCanBill: false,
    scope: "team",
    confidence: "low",
    evidence,
    strategy: "format-decode",
  };
}

function metadataFor(input: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(input).filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
}

function authHeaders(ctx: AuthContext): Record<string, string> {
  return {
    Authorization: `Bearer ${ctx.token}`,
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

function unsupported(message: string): RotationResult<never> {
  return {
    ok: false,
    error: makeError("unsupported", message, PROVIDER, { retryable: false }),
  };
}

function networkError(cause: Error) {
  return makeError("network_error", `${PROVIDER}: network error`, PROVIDER, { cause });
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `${PROVIDER} ${op}: ${res.status}`, PROVIDER);
  }
  if (res.status === 429) {
    return makeError("rate_limited", `${PROVIDER} ${op}: 429`, PROVIDER);
  }
  if (res.status === 404) {
    return makeError("not_found", `${PROVIDER} ${op}: 404`, PROVIDER);
  }
  if (res.status >= 500) {
    return makeError("provider_error", `${PROVIDER} ${op}: ${res.status}`, PROVIDER);
  }
  return makeError("provider_error", `${PROVIDER} ${op}: ${res.status}`, PROVIDER, {
    retryable: false,
  });
}
