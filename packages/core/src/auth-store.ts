import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { AuthContext, AuthStoredCredential } from "./types.ts";

function getStateDir(): string {
  const configured = process.env.ROTATE_CLI_STATE_DIR;
  if (configured) return configured;
  const home = process.env.HOME;
  if (!home) throw new Error("rotate auth unavailable: HOME is not set");
  return join(home, ".config", "rotate-cli");
}

export function getAuthStoreDir(): string {
  return join(getStateDir(), "auth");
}

export function getAuthStorePath(name: string): string {
  return join(getAuthStoreDir(), `${name}.json`);
}

export function readStoredCredential(name: string): AuthStoredCredential | undefined {
  const path = getAuthStorePath(name);
  if (!existsSync(path)) return undefined;
  const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<AuthStoredCredential>;
  if (typeof parsed.token !== "string" || typeof parsed.updatedAt !== "string") {
    throw new Error(`rotate auth store invalid: ${path}`);
  }
  return {
    token: parsed.token,
    updatedAt: parsed.updatedAt,
    source: "manual",
  };
}

export function readStoredAuthContext(name: string): AuthContext | undefined {
  const credential = readStoredCredential(name);
  if (!credential) return undefined;
  return {
    kind: "encrypted-file",
    path: getAuthStorePath(name),
    token: credential.token,
  };
}

export function writeStoredCredential(name: string, token: string): string {
  const path = getAuthStorePath(name);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(
    path,
    JSON.stringify(
      {
        token,
        updatedAt: new Date().toISOString(),
        source: "manual",
      } satisfies AuthStoredCredential,
      null,
      2,
    ),
    { mode: 0o600 },
  );
  try {
    chmodSync(path, 0o600);
  } catch {
    // Best effort only.
  }
  return path;
}

export function deleteStoredCredential(name: string): boolean {
  const path = getAuthStorePath(name);
  if (!existsSync(path)) return false;
  rmSync(path);
  return true;
}
