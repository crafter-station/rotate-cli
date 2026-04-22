import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

export const triggerDevAuthDefinition: AuthDefinition = {
  name: "trigger-dev",
  displayName: "Trigger.dev",
  envVars: ["TRIGGER_SECRET_KEY", "TRIGGER_ACCESS_TOKEN"],
  setupUrl: "https://cloud.trigger.dev",
  notes: [
    "Uses TRIGGER_SECRET_KEY for runtime API verification. TRIGGER_ACCESS_TOKEN is a separate dashboard/CLI credential and is not used for project secret rotation.",
  ],
  methods: [
    {
      id: "paste-secret-key",
      label: "Paste project secret key",
      description: "Copy a project environment secret key from the Trigger.dev dashboard",
      steps: [
        {
          kind: "note",
          message:
            "Trigger.dev API keys: https://cloud.trigger.dev\nOpen your project, choose the target environment, open API Keys, then paste the Secret API key below.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste Trigger.dev project secret key",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitTriggerDevKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.TRIGGER_SECRET_KEY;
    if (envToken) {
      return { kind: "env", varName: "TRIGGER_SECRET_KEY", token: envToken };
    }
    const stored = readStoredAuthContext("trigger-dev");
    if (stored) return stored;
    throw new Error(
      "trigger-dev auth unavailable: set TRIGGER_SECRET_KEY or run `rotate auth login trigger-dev`",
    );
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste Trigger.dev project secret key");
    return submitTriggerDevKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyTriggerDevAuth(ctx);
  },
};

async function submitTriggerDevKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("trigger-dev auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "TRIGGER_SECRET_KEY", token };
  await verifyTriggerDevAuth(ctx);
  const path = writeStoredCredential("trigger-dev", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyTriggerDevAuth(ctx: AuthContext): Promise<void> {
  const res = await request(`${apiBase()}/api/v1/query/schema`, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`trigger-dev verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`trigger-dev verify failed: ${res.status}`);
  }
}

function apiBase(): string {
  const base =
    process.env.TRIGGER_API_URL ?? process.env.TRIGGER_DEV_API_URL ?? "https://api.trigger.dev";
  return base.replace(/\/+$/, "");
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
