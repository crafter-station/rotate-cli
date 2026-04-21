import * as prompts from "@clack/prompts";
import type { AuthListEntry } from "./types.ts";

export function renderAuthList(entries: AuthListEntry[]): void {
  if (!entries.length) {
    prompts.note("No auth providers are registered.", "Auth Providers");
    return;
  }

  prompts.note(
    entries
      .map((entry) => {
        const status = entry.status === "configured" ? `configured (${entry.source})` : "missing";
        return `${entry.displayName}: ${status}`;
      })
      .join("\n"),
    "Auth Providers",
  );
}

export function renderAuthLoginSuccess(input: {
  displayName: string;
  source: string;
  envVars: string[];
  setupUrl?: string;
}): void {
  prompts.outro(
    [
      `${input.displayName} is configured.`,
      `Source: ${input.source}`,
      `Env: ${input.envVars.join(", ")}`,
      input.setupUrl ? `Setup: ${input.setupUrl}` : undefined,
      "Next: rotate auth list",
      "Then: rotate doctor",
    ]
      .filter(Boolean)
      .join("\n"),
  );
}

export function renderAuthLogoutResult(input: {
  displayName: string;
  removed: boolean;
  envStillConfigured: boolean;
  envVars: string[];
}): void {
  prompts.outro(
    [
      input.removed
        ? `${input.displayName} stored auth was removed.`
        : `${input.displayName} had no stored auth to remove.`,
      input.envStillConfigured
        ? `${input.displayName} still resolves from ${input.envVars.join(", ")}.`
        : `${input.displayName} is no longer configured in rotate-cli storage.`,
    ].join("\n"),
  );
}
