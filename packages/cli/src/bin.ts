#!/usr/bin/env bun
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { runCli } from "@rotate/core";
import { registerAll } from "./register.ts";

// Auto-load local .env files from CWD (Next.js / Vite style).
// Shell exports and CI env vars ALWAYS win — loadDotEnv never overwrites.
loadDotEnv();

registerAll();

runCli(process.argv).catch((err) => {
  process.stderr.write(`${String(err)}\n`);
  process.exit(1);
});

function loadDotEnv(): void {
  // Precedence: highest wins. We load in REVERSE precedence so the last
  // load sets what the first load would have. Simpler: only set if absent.
  //
  // .env.local        — gitignored, user-specific overrides (highest)
  // .env.development  — dev defaults
  // .env              — shared defaults (lowest)
  const files = [".env", ".env.development", ".env.local"];
  for (const f of files) {
    const path = resolve(process.cwd(), f);
    if (!existsSync(path)) continue;
    try {
      const raw = readFileSync(path, "utf8");
      for (const line of raw.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const eq = trimmed.indexOf("=");
        if (eq < 1) continue;
        const key = trimmed.slice(0, eq).trim();
        if (process.env[key] !== undefined) continue;
        let value = trimmed.slice(eq + 1).trim();
        // Strip surrounding quotes (single or double) if balanced.
        if (
          (value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))
        ) {
          value = value.slice(1, -1);
        }
        process.env[key] = value;
      }
    } catch {
      // Parse/IO errors: fall through silently. The CLI will surface them
      // as auth-failed on the specific adapter.
    }
  }
}
