import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Checkpoint, Rotation } from "./types.ts";

const DEFAULT_STATE_DIR = join(homedir(), ".config", "rotate-cli");

export function stateDir(): string {
  return process.env.ROTATE_CLI_STATE_DIR ?? DEFAULT_STATE_DIR;
}

function dirs() {
  const base = stateDir();
  return {
    base,
    state: join(base, "state"),
    history: join(base, "history"),
    audit: join(base, "audit"),
  };
}

export function ensureStateDirs(): void {
  const d = dirs();
  for (const path of [d.base, d.state, d.history, d.audit]) {
    if (!existsSync(path)) mkdirSync(path, { recursive: true });
  }
}

export function saveCheckpoint(checkpoint: Checkpoint): void {
  ensureStateDirs();
  const path = join(dirs().state, `${checkpoint.rotationId}.json`);
  writeFileSync(path, JSON.stringify(checkpoint, null, 2), "utf8");
}

export function loadCheckpoint(rotationId: string): Checkpoint | null {
  const path = join(dirs().state, `${rotationId}.json`);
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as Checkpoint;
}

export function listCheckpoints(): Checkpoint[] {
  ensureStateDirs();
  const entries = readdirSync(dirs().state).filter((f) => f.endsWith(".json"));
  return entries.map((f) => JSON.parse(readFileSync(join(dirs().state, f), "utf8")) as Checkpoint);
}

export function archiveToHistory(rotation: Rotation): void {
  ensureStateDirs();
  const month = new Date(rotation.startedAt).toISOString().slice(0, 7);
  const path = join(dirs().history, `${month}.jsonl`);
  const line = `${JSON.stringify(rotation)}\n`;
  const existing = existsSync(path) ? readFileSync(path, "utf8") : "";
  writeFileSync(path, existing + line, "utf8");
  // Remove in-progress checkpoint.
  const stateFile = join(dirs().state, `${rotation.id}.json`);
  if (existsSync(stateFile)) {
    // Use a write-then-unlink to avoid data loss on crash.
    writeFileSync(stateFile, JSON.stringify({ archived: true }));
    try {
      // biome-ignore lint/suspicious/noExplicitAny: node rm typing
      (require("node:fs") as any).unlinkSync(stateFile);
    } catch {
      /* ignore */
    }
  }
}

export function appendAudit(path: string | undefined, entry: Record<string, unknown>): void {
  if (!path) return;
  const abs = path.startsWith("/") ? path : join(process.cwd(), path);
  const existing = existsSync(abs) ? readFileSync(abs, "utf8") : "";
  writeFileSync(abs, `${existing}${JSON.stringify(entry)}\n`, "utf8");
}

export function generateRotationId(): string {
  const chars = "abcdefghjkmnpqrstuvwxyz23456789";
  let id = "rot_";
  for (let i = 0; i < 12; i++) id += chars[Math.floor(Math.random() * chars.length)];
  return id;
}
