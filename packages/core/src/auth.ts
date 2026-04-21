import { deleteStoredCredential, readStoredAuthContext } from "./auth-store.ts";
import { makeError } from "./errors.ts";
import type { Adapter, AuthDefinition, AuthListEntry, AuthSummary, Consumer } from "./types.ts";
import { listAdapters, listConsumers } from "./registry.ts";

const authDefinitions = new Map<string, AuthDefinition>();

export function registerAuthDefinition(definition: AuthDefinition): void {
  if (authDefinitions.has(definition.name)) {
    throw new Error(`auth definition already registered: ${definition.name}`);
  }
  authDefinitions.set(definition.name, definition);
}

export function getAuthDefinition(name: string): AuthDefinition | undefined {
  return authDefinitions.get(name);
}

export function listAuthDefinitions(): AuthDefinition[] {
  return [...authDefinitions.values()];
}

export function resetAuthDefinitions(): void {
  authDefinitions.clear();
}

export async function resolveRegisteredAuth(name: string) {
  const definition = getRequiredAuthDefinition(name);
  return definition.resolve();
}

export async function logoutRegisteredAuth(name: string): Promise<boolean> {
  const definition = getRequiredAuthDefinition(name);
  if (definition.logout) return definition.logout();
  return deleteStoredCredential(name);
}

export function readRegisteredStoredAuth(name: string) {
  return readStoredAuthContext(name);
}

export function buildAuthSummary(name: string): AuthSummary {
  const definition = getRequiredAuthDefinition(name);
  return {
    name: definition.name,
    displayName: definition.displayName,
    envVars: definition.envVars,
    setupUrl: definition.setupUrl,
    notes: definition.notes,
  };
}

export async function listAuthEntries(): Promise<AuthListEntry[]> {
  const entries = await Promise.all(
    listAuthDefinitions().map(async (definition) => {
      const stored = readStoredAuthContext(definition.name);
      const usedBy = findAuthUsers(definition.name);
      const envVar = definition.envVars.find((name) => Boolean(process.env[name]));
      return {
        name: definition.name,
        displayName: definition.displayName,
        status: envVar || stored ? "configured" : "missing",
        source: envVar ? "env" : stored ? "stored" : "none",
        envVars: definition.envVars,
        setupUrl: definition.setupUrl,
        usedBy,
      } satisfies AuthListEntry;
    }),
  );
  return entries.sort((a, b) => a.displayName.localeCompare(b.displayName));
}

function getRequiredAuthDefinition(name: string): AuthDefinition {
  const definition = getAuthDefinition(name);
  if (definition) return definition;
  throw makeError("invalid_spec", `unknown auth provider: ${name}`, "rotate-cli", {
    retryable: false,
  });
}

function findAuthUsers(name: string): Array<{ kind: "adapter" | "consumer"; name: string }> {
  return [...listNamedAuthUsers(listAdapters(), "adapter", name), ...listNamedAuthUsers(listConsumers(), "consumer", name)];
}

function listNamedAuthUsers<T extends Adapter | Consumer>(
  values: T[],
  kind: "adapter" | "consumer",
  authName: string,
) {
  return values
    .filter((value) => (value.authRef ?? value.name) === authName)
    .map((value) => ({ kind, name: value.name }));
}
