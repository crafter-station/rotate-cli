/**
 * Scan Vercel for every env var across every accessible team + project, map
 * each to a rotate-cli adapter, and return a synthetic plan the orchestrator
 * can feed into preview-ownership / apply without needing a hand-written
 * rotate.config.yaml.
 *
 * This is "golpear contra todo": the user gets a live audit of every secret
 * they can see on Vercel, ownership-checked against their admin keys.
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import type { ConsumerTargetConfig, SecretConfig } from "./types.ts";

const VERCEL_BASE = process.env.VERCEL_API_URL ?? "https://api.vercel.com";

// Map env var name → rotate-cli adapter name. Ordered from most specific to
// most generic. An unmapped var is returned as `adapter: null` so the caller
// can skip it (not every env var is a rotatable secret — some are config).
const VAR_TO_ADAPTER: Array<{ match: (name: string) => boolean; adapter: string }> = [
  // clerk
  { match: (n) => n === "CLERK_SECRET_KEY" || n === "CLERK_WEBHOOK_SECRET", adapter: "clerk" },
  // openai / anthropic / fal / elevenlabs / groq / mistral / ai-gateway
  { match: (n) => n === "OPENAI_API_KEY" || n === "OPENAI_ADMIN_KEY", adapter: "openai" },
  { match: (n) => n === "ANTHROPIC_API_KEY" || n === "ANTHROPIC_ADMIN_KEY", adapter: "anthropic" },
  { match: (n) => n === "FAL_API_KEY" || n === "FAL_KEY", adapter: "fal" },
  { match: (n) => n === "ELEVENLABS_API_KEY", adapter: "elevenlabs" },
  { match: (n) => n === "AI_GATEWAY_API_KEY", adapter: "vercel-ai-gateway" },
  // email
  { match: (n) => n === "RESEND_API_KEY", adapter: "resend" },
  // db
  {
    match: (n) =>
      /^(DATABASE_URL|POSTGRES_URL|POSTGRES_URL_NON_POOLING|POSTGRES_PRISMA_URL|DATABASE_URL_UNPOOLED)$/.test(
        n,
      ),
    adapter: "neon-connection",
  },
  { match: (n) => n === "NEON_API_KEY", adapter: "neon" },
  {
    match: (n) =>
      n === "SUPABASE_SERVICE_ROLE_KEY" || n === "SUPABASE_ANON_KEY" || n === "SUPABASE_JWT_SECRET",
    adapter: "supabase",
  },
  { match: (n) => n === "TURSO_AUTH_TOKEN" || n === "TURSO_DATABASE_URL", adapter: "turso" },
  // cache / kv
  {
    match: (n) =>
      /^UPSTASH_(REDIS_)?(REST_)?(URL|TOKEN)$/.test(n) || /^UPSTASH_VECTOR_REST/.test(n),
    adapter: "upstash",
  },
  { match: (n) => /^KV_(REST_API_)?(URL|TOKEN|READ_ONLY_TOKEN)$/.test(n), adapter: "vercel-kv" },
  // infra tokens
  { match: (n) => n === "VERCEL_TOKEN" || n === "VERCEL_API_TOKEN", adapter: "vercel-token" },
  { match: (n) => n === "GITHUB_TOKEN" || n === "GH_TOKEN", adapter: "github-token" },
  // billing
  { match: (n) => n === "POLAR_ACCESS_TOKEN" || n === "POLAR_WEBHOOK_SECRET", adapter: "polar" },
  // app secrets — generated locally, no provider
  {
    match: (n) =>
      /^(SESSION_SECRET|JWT_SECRET|HMAC_SECRET|CRON_SECRET|AUTH_SECRET|NEXTAUTH_SECRET)$/.test(n),
    adapter: "local-random",
  },
];

export function mapVarToAdapter(name: string): string | null {
  for (const rule of VAR_TO_ADAPTER) {
    if (rule.match(name)) return rule.adapter;
  }
  return null;
}

export interface ScanOptions {
  token: string;
  teamSlug?: string; // limit to a single team
  includePublic?: boolean; // NEXT_PUBLIC_* vars (default: false)
  /** Called on every lifecycle event so the CLI can render live progress. */
  onProgress?: (event: ScanProgressEvent) => void;
  /** Parallelism for project env-var fetches within a single team. */
  concurrency?: number;
}

export type ScanProgressEvent =
  | { kind: "teams-discovered"; teams: string[] }
  | { kind: "team-start"; team: string; totalProjects: number }
  | {
      kind: "team-progress";
      team: string;
      projectsScanned: number;
      totalProjects: number;
      secretsSoFar: number;
    }
  | {
      kind: "team-done";
      team: string;
      projectsScanned: number;
      secretsFound: number;
      durationMs: number;
    }
  | { kind: "team-skipped"; team: string; reason: string };

export interface ScannedSecret extends SecretConfig {
  _scanned: true;
  _project: string;
  _team?: string;
  _varType: string;
}

export async function scanVercel(opts: ScanOptions): Promise<{
  secrets: ScannedSecret[];
  skipped: Array<{ var_name: string; project: string; reason: string }>;
  teamsScanned: string[];
  projectsScanned: number;
}> {
  const headers = { Authorization: `Bearer ${opts.token}` };
  const DASHBOARD_BASE = "https://vercel.com";

  // 1. Enumerate scopes the token can actually see.
  //
  // Vercel tokens come in two shapes: user-scoped (ve personal + every team
  // the user belongs to) and team-scoped (ve solo un team). We hit /v2/teams
  // to enumerate what the token owns. If the user passed --team we respect
  // that. If /v2/teams is empty we assume a pure-personal hobby account
  // and fall back to the no-teamId scope.
  const teams: Array<{ id?: string; slug: string }> = [];
  if (opts.teamSlug) {
    // User-provided slug → resolve to an id so we can use teamId in requests.
    const res = await fetch(`${VERCEL_BASE}/v2/teams?limit=50`, { headers });
    if (!res.ok) throw new Error(`vercel list teams failed: ${res.status}`);
    const body = (await res.json()) as { teams?: Array<{ id: string; slug: string }> };
    const match = body.teams?.find((t) => t.slug === opts.teamSlug);
    if (match) teams.push({ id: match.id, slug: match.slug });
    else teams.push({ slug: opts.teamSlug }); // fallback (may 404)
  } else {
    const res = await fetch(`${VERCEL_BASE}/v2/teams?limit=50`, { headers });
    if (!res.ok) throw new Error(`vercel list teams failed: ${res.status}`);
    const body = (await res.json()) as { teams?: Array<{ id: string; slug: string }> };
    const accessibleTeams = body.teams ?? [];
    if (accessibleTeams.length > 0) {
      for (const t of accessibleTeams) teams.push({ id: t.id, slug: t.slug });
    } else {
      // Hobby account with no team membership — only personal scope available.
      teams.push({ slug: "personal" });
    }
  }

  opts.onProgress?.({ kind: "teams-discovered", teams: teams.map((t) => t.slug) });

  const secrets: ScannedSecret[] = [];
  const skipped: Array<{ var_name: string; project: string; reason: string }> = [];
  let projectsScanned = 0;
  const concurrency = opts.concurrency ?? 6;

  for (const team of teams) {
    const teamStarted = Date.now();
    const teamIdQs = team.id ? `teamId=${team.id}` : "";

    // Primary path: /api/dashboard/environment-variables returns every
    // project's env vars in a single call and bypasses the 300-project cap
    // of the public /v9/projects pagination. Same access token works.
    const dashUrl = team.id
      ? `${DASHBOARD_BASE}/api/dashboard/environment-variables?teamId=${team.id}`
      : `${DASHBOARD_BASE}/api/dashboard/environment-variables`;
    const dashRes = await fetch(dashUrl, { headers });
    if (dashRes.ok) {
      const dashBody = (await dashRes.json()) as {
        projectEnvs?: Array<{
          project: string;
          envs: Array<{ id: string; key: string; type: string; target?: string[] }>;
        }>;
        meta?: { truncated?: boolean; totalProjectCount?: number };
      };
      const projectEnvs = dashBody.projectEnvs ?? [];
      const totalProjects = dashBody.meta?.totalProjectCount ?? projectEnvs.length;
      const truncated = Boolean(dashBody.meta?.truncated);

      opts.onProgress?.({
        kind: "team-start",
        team: team.slug,
        totalProjects,
      });

      const seenProjectNames = new Set<string>();
      let teamSecretsFound = 0;

      const ingest = (args: {
        projectName: string;
        projectId?: string;
        envs: Array<{ id: string; key: string; type: string; target?: string[] }>;
      }): void => {
        if (seenProjectNames.has(args.projectName)) return;
        seenProjectNames.add(args.projectName);
        for (const env of args.envs) {
          if (!opts.includePublic && env.key.startsWith("NEXT_PUBLIC_")) continue;
          if (env.key === "NODE_ENV" || env.key === "VERCEL_ENV") continue;
          const adapter = mapVarToAdapter(env.key);
          if (!adapter) {
            skipped.push({
              var_name: env.key,
              project: args.projectName,
              reason: "no adapter mapping",
            });
            continue;
          }
          const consumer: ConsumerTargetConfig = {
            type: "vercel-env",
            params: {
              project: args.projectId ?? args.projectName,
              var_name: env.key,
              ...(team.id ? { team: team.id } : {}),
            },
          };
          secrets.push({
            _scanned: true,
            _project: args.projectName,
            _team: team.slug,
            _varType: env.type,
            id: `${adapter}-${args.projectName}-${env.key}`.slice(0, 120),
            adapter,
            metadata: {},
            tags:
              env.type === "sensitive" || env.type === "secret" ? ["sensitive"] : ["non-sensitive"],
            consumers: [consumer],
          });
          teamSecretsFound++;
        }
      };

      for (let i = 0; i < projectEnvs.length; i++) {
        const pe = projectEnvs[i]!;
        ingest({ projectName: pe.project, envs: pe.envs });
        projectsScanned++;
        opts.onProgress?.({
          kind: "team-progress",
          team: team.slug,
          projectsScanned: i + 1,
          totalProjects,
          secretsSoFar: teamSecretsFound,
        });
      }

      // If truncated, fill the gap via /v9/projects + per-project /env.
      // Dedupe against the names we already ingested.
      if (truncated && projectEnvs.length < totalProjects) {
        const allProjects: Array<{ id: string; name: string }> = [];
        let cursor: string | null = null;
        for (;;) {
          const parts = ["limit=100"];
          if (teamIdQs) parts.push(teamIdQs);
          if (cursor) parts.push(`until=${cursor}`);
          const r = await fetch(`${VERCEL_BASE}/v9/projects?${parts.join("&")}`, {
            headers,
          });
          if (!r.ok) break;
          const b = (await r.json()) as {
            projects?: Array<{ id: string; name: string }>;
            pagination?: { next: string | null };
          };
          allProjects.push(...(b.projects ?? []));
          if (!b.pagination?.next) break;
          cursor = b.pagination.next;
        }
        const missing = allProjects.filter((p) => !seenProjectNames.has(p.name));
        let scanned = projectEnvs.length;
        const queue = [...missing];
        await Promise.all(
          Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
            while (queue.length) {
              const proj = queue.shift();
              if (!proj) continue;
              const envUrl = team.id
                ? `${VERCEL_BASE}/v9/projects/${proj.id}/env?decrypt=false&teamId=${team.id}`
                : `${VERCEL_BASE}/v9/projects/${proj.id}/env?decrypt=false`;
              const er = await fetch(envUrl, { headers });
              if (er.ok) {
                const eb = (await er.json()) as {
                  envs?: Array<{ id: string; key: string; type: string; target?: string[] }>;
                };
                ingest({
                  projectName: proj.name,
                  projectId: proj.id,
                  envs: eb.envs ?? [],
                });
              }
              projectsScanned++;
              scanned++;
              opts.onProgress?.({
                kind: "team-progress",
                team: team.slug,
                projectsScanned: scanned,
                totalProjects,
                secretsSoFar: teamSecretsFound,
              });
            }
          }),
        );
      }

      opts.onProgress?.({
        kind: "team-done",
        team: team.slug,
        projectsScanned: seenProjectNames.size,
        secretsFound: teamSecretsFound,
        durationMs: Date.now() - teamStarted,
      });
      continue;
    }

    // Fallback path (public API /v9/projects + /env per project). Capped at
    // 300 projects by Vercel. Used only when the dashboard endpoint fails,
    // e.g. token lacks web-session privileges.
    const projList: Array<{ id: string; name: string }> = [];
    let cursor: string | null = null;
    let paginationFailed = false;
    for (;;) {
      const parts = ["limit=100"];
      if (teamIdQs) parts.push(teamIdQs);
      if (cursor) parts.push(`until=${cursor}`);
      const projRes = await fetch(`${VERCEL_BASE}/v9/projects?${parts.join("&")}`, {
        headers,
      });
      if (!projRes.ok) {
        paginationFailed = true;
        opts.onProgress?.({
          kind: "team-skipped",
          team: team.slug,
          reason: `projects ${projRes.status}`,
        });
        break;
      }
      const projBody = (await projRes.json()) as {
        projects?: Array<{ id: string; name: string }>;
        pagination?: { next: string | null };
      };
      projList.push(...(projBody.projects ?? []));
      if (!projBody.pagination?.next) break;
      cursor = projBody.pagination.next;
    }
    if (paginationFailed) continue;
    opts.onProgress?.({
      kind: "team-start",
      team: team.slug,
      totalProjects: projList.length,
    });

    let teamProjectsDone = 0;
    let teamSecretsFound = 0;

    async function scanProject(proj: { id: string; name: string }): Promise<void> {
      const envUrl = teamIdQs
        ? `${VERCEL_BASE}/v9/projects/${proj.id}/env?decrypt=false&${teamIdQs}`
        : `${VERCEL_BASE}/v9/projects/${proj.id}/env?decrypt=false`;
      const envRes = await fetch(envUrl, { headers });
      if (envRes.ok) {
        const envBody = (await envRes.json()) as {
          envs?: Array<{ id: string; key: string; type: string; target?: string[] }>;
        };
        for (const env of envBody.envs ?? []) {
          if (!opts.includePublic && env.key.startsWith("NEXT_PUBLIC_")) continue;
          if (env.key === "NODE_ENV" || env.key === "VERCEL_ENV") continue;
          const adapter = mapVarToAdapter(env.key);
          if (!adapter) {
            skipped.push({
              var_name: env.key,
              project: proj.name,
              reason: "no adapter mapping",
            });
            continue;
          }
          const consumer: ConsumerTargetConfig = {
            type: "vercel-env",
            params: {
              project: proj.id,
              var_name: env.key,
              ...(team.id ? { team: team.id } : {}),
            },
          };
          secrets.push({
            _scanned: true,
            _project: proj.name,
            _team: team.slug,
            _varType: env.type,
            id: `${adapter}-${proj.name}-${env.key}`.slice(0, 120),
            adapter,
            metadata: {},
            tags:
              env.type === "sensitive" || env.type === "secret" ? ["sensitive"] : ["non-sensitive"],
            consumers: [consumer],
          });
          teamSecretsFound++;
        }
      }
      projectsScanned++;
      teamProjectsDone++;
      opts.onProgress?.({
        kind: "team-progress",
        team: team.slug,
        projectsScanned: teamProjectsDone,
        totalProjects: projList.length,
        secretsSoFar: teamSecretsFound,
      });
    }

    // Consume projList in `concurrency`-wide chunks so the dashboard shows
    // smooth progress instead of blocking on each project sequentially.
    const queue = [...projList];
    await Promise.all(
      Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
        while (queue.length) {
          const next = queue.shift();
          if (next) await scanProject(next);
        }
      }),
    );

    opts.onProgress?.({
      kind: "team-done",
      team: team.slug,
      projectsScanned: teamProjectsDone,
      secretsFound: teamSecretsFound,
      durationMs: Date.now() - teamStarted,
    });
  }

  return {
    secrets,
    skipped,
    teamsScanned: teams.map((t) => t.slug),
    projectsScanned,
  };
}

/**
 * Fetch decrypted env vars for a batch of Vercel projects, keyed by project
 * slug (name). Used by `who` + `apply` to populate coLocatedVars on-demand
 * so adapters can do sibling-inheritance (clerk reads CLERK_PUBLISHABLE_KEY,
 * supabase reads SUPABASE_URL, etc.).
 *
 * Returns a Map<projectSlug, Record<envName, envValue>>. Failures per
 * project are swallowed — absent keys just mean no siblings available.
 *
 * Why slug → id resolution is required: the scan cache stores project
 * slugs (not ids) as the `project` field on each secret's vercel-env
 * consumer. But /v9/projects/{id}/env expects an actual project id. So
 * this function first enumerates all projects to build a slug→id map,
 * then fans out env fetches by id, and finally re-keys the result by
 * slug so callers can look it up with the scan cache key.
 */
export async function fetchProjectSiblings(args: {
  token: string;
  projects: Array<{ key: string; teamId?: string }>;
  concurrency?: number;
}): Promise<Map<string, Record<string, string>>> {
  const result = new Map<string, Record<string, string>>();
  const headers = { Authorization: `Bearer ${args.token}` };
  const concurrency = args.concurrency ?? 10;
  // Dedupe — many secrets share the same project.
  const seen = new Set<string>();
  const deduped = args.projects.filter((p) => {
    const k = `${p.teamId ?? ""}:${p.key}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  if (deduped.length === 0) return result;

  // Step 1: enumerate all projects per team to build a slug → id map.
  // Vercel caps /v9/projects at 3 pages × 100, so we fall back to the
  // dashboard endpoint (which returns every project in a single call).
  const teamIds = new Set<string>();
  for (const p of deduped) {
    if (p.teamId) teamIds.add(p.teamId);
    else teamIds.add("");
  }

  const slugToId = new Map<string, { id: string; teamId?: string }>();
  for (const teamId of teamIds) {
    const dashUrl = teamId
      ? `https://vercel.com/api/dashboard/environment-variables?teamId=${teamId}`
      : "https://vercel.com/api/dashboard/environment-variables";
    try {
      const dashRes = await fetch(dashUrl, { headers });
      if (dashRes.ok) {
        const dashBody = (await dashRes.json()) as {
          projectEnvs?: Array<{ projectId?: string; project: string }>;
        };
        for (const pe of dashBody.projectEnvs ?? []) {
          if (pe.projectId) {
            slugToId.set(pe.project, { id: pe.projectId, teamId: teamId || undefined });
          }
        }
      }
    } catch {
      /* dashboard endpoint unavailable — fall through to /v9/projects */
    }

    // Fallback + fill gaps: /v9/projects paginated.
    let cursor: string | null = null;
    for (;;) {
      const parts = ["limit=100"];
      if (teamId) parts.push(`teamId=${teamId}`);
      if (cursor) parts.push(`until=${cursor}`);
      try {
        const res = await fetch(`${VERCEL_BASE}/v9/projects?${parts.join("&")}`, { headers });
        if (!res.ok) break;
        const body = (await res.json()) as {
          projects?: Array<{ id: string; name: string }>;
          pagination?: { next: string | null };
        };
        for (const p of body.projects ?? []) {
          if (!slugToId.has(p.name)) {
            slugToId.set(p.name, { id: p.id, teamId: teamId || undefined });
          }
        }
        if (!body.pagination?.next) break;
        cursor = body.pagination.next;
      } catch {
        break;
      }
    }
  }

  // Step 2: fan out /env (list) + per-env /v1 decrypt by project id, re-key
  // result by slug. Vercel's /v9/env only returns encrypted blobs even with
  // decrypt=true — actual plaintext requires /v1/projects/{id}/env/{envId}
  // which is per-env. Each decrypt call gets a 10s timeout.
  //
  // Limitation: `sensitive` type env vars NEVER return plaintext — Vercel
  // docs say this explicitly. They'll be missing from the result map; that's
  // fine since the caller treats absent siblings as "no hint available".
  const queue = deduped.map((p) => ({
    slug: p.key,
    resolved: slugToId.get(p.key),
  }));

  async function fetchWithTimeout(url: string, timeoutMs = 10_000): Promise<Response | null> {
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      return await fetch(url, { headers, signal: ctrl.signal });
    } catch {
      return null;
    } finally {
      clearTimeout(tid);
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
      while (queue.length) {
        const proj = queue.shift();
        if (!proj?.resolved) continue;
        const { id, teamId } = proj.resolved;
        const teamQs = teamId ? `&teamId=${teamId}` : "";

        // List envs (no decrypt — we just need the ids + types).
        const listRes = await fetchWithTimeout(
          `${VERCEL_BASE}/v9/projects/${id}/env?decrypt=false${teamQs ? `&teamId=${teamId}` : ""}`,
        );
        if (!listRes?.ok) continue;
        const listBody = (await listRes.json()) as {
          envs?: Array<{ id: string; key: string; type: string }>;
        };

        // Only decrypt non-sensitive vars. Sensitive types return `<none>`
        // regardless, so skipping them saves N requests per project.
        const decryptable = (listBody.envs ?? []).filter(
          (e) => e.type !== "sensitive" && e.type !== "secret" && e.id && e.key,
        );

        // Decrypt in parallel within the project (inner concurrency=5 so we
        // don't pile on too aggressively — outer loop already has outer
        // concurrency, total is concurrency*5 in flight).
        const vars: Record<string, string> = {};
        const envQueue = [...decryptable];
        await Promise.all(
          Array.from({ length: Math.min(5, envQueue.length) }, async () => {
            while (envQueue.length) {
              const env = envQueue.shift();
              if (!env) continue;
              const decUrl = `${VERCEL_BASE}/v1/projects/${id}/env/${env.id}?decrypt=true${teamQs}`;
              const decRes = await fetchWithTimeout(decUrl);
              if (!decRes?.ok) continue;
              const decBody = (await decRes.json()) as { value?: string };
              if (typeof decBody.value === "string" && decBody.value.length > 0) {
                vars[env.key] = decBody.value;
              }
            }
          }),
        );
        result.set(proj.slug, vars);
      }
    }),
  );

  return result;
}

export function resolveVercelTokenForScan(): string | null {
  if (process.env.VERCEL_TOKEN) return process.env.VERCEL_TOKEN;
  const paths =
    platform() === "darwin"
      ? [
          join(homedir(), "Library", "Application Support", "com.vercel.cli", "auth.json"),
          join(homedir(), ".local", "share", "com.vercel.cli", "auth.json"),
        ]
      : [
          join(homedir(), ".local", "share", "com.vercel.cli", "auth.json"),
          join(homedir(), ".config", "vercel", "auth.json"),
        ];
  for (const p of paths) {
    if (!existsSync(p)) continue;
    try {
      const t = JSON.parse(readFileSync(p, "utf8")).token;
      if (typeof t === "string" && t.length > 0) return t;
    } catch {
      /* keep trying */
    }
  }
  return null;
}
