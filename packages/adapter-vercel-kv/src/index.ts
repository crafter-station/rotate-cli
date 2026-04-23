/**
 * @rotate/adapter-vercel-kv — thin wrapper over @rotate/adapter-upstash.
 *
 * Vercel KV was officially discontinued in Dec 2024 and existing stores
 * were auto-migrated to Upstash Redis. The KV_* env vars that remain in
 * old projects still point at an Upstash-managed database.
 * Ref: https://vercel.com/docs/redis
 *
 * So this adapter delegates every operation to adapter-upstash and only
 * exists to keep rotate.config.yaml readable (`adapter: vercel-kv` maps
 * cleanly to KV_REST_API_TOKEN / KV_URL vars).
 *
 * Auth: same as upstash — env UPSTASH_EMAIL + UPSTASH_API_KEY, OR
 * VERCEL_KV_EMAIL + VERCEL_KV_API_KEY (aliases for discoverability).
 *
 * metadata: { database_id: string }  — same as upstash.
 */

import upstashAdapter from "@rotate/adapter-upstash";
import type { Adapter, AuthContext } from "@rotate/core/types";

export const vercelKvAdapter: Adapter = {
  name: "vercel-kv",
  mode: "no-check",

  async auth(): Promise<AuthContext> {
    // Alias: allow Vercel-branded env vars so users who think of this as
    // "Vercel KV" don't need to know the underlying provider.
    if (process.env.VERCEL_KV_EMAIL && !process.env.UPSTASH_EMAIL) {
      process.env.UPSTASH_EMAIL = process.env.VERCEL_KV_EMAIL;
    }
    if (process.env.VERCEL_KV_API_KEY && !process.env.UPSTASH_API_KEY) {
      process.env.UPSTASH_API_KEY = process.env.VERCEL_KV_API_KEY;
    }
    return upstashAdapter.auth();
  },

  create: upstashAdapter.create,
  verify: upstashAdapter.verify,
  revoke: upstashAdapter.revoke,
  list: upstashAdapter.list,
};

export default vercelKvAdapter;
