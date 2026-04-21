import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const TURSO_AUTH_VALIDATE_URL =
  process.env.TURSO_AUTH_VALIDATE_URL ?? "https://api.turso.tech/v1/auth/validate";

export const tursoAuthDefinition: AuthDefinition = {
  name: "turso",
  displayName: "Turso",
  envVars: ["TURSO_PLATFORM_TOKEN"],
  setupUrl: "https://turso.tech/app/settings/tokens",
  notes: ["Platform-scope token. Run `turso auth api-tokens mint rotate-cli` to create one."],
  methods: [
    {
      id: "paste-platform-key",
      label: "Paste Turso platform token",
      description: "Create a platform-scope token in Turso and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "Turso platform tokens: https://turso.tech/app/settings/tokens\nRun `turso auth api-tokens mint rotate-cli` to create one, then paste it below.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste Turso platform token",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitTursoKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.TURSO_PLATFORM_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "TURSO_PLATFORM_TOKEN", token: envToken };
    }
    const stored = readStoredAuthContext("turso");
    if (stored) return stored;
    throw new Error(
      "turso auth unavailable: set TURSO_PLATFORM_TOKEN or run `rotate auth login turso`",
    );
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste Turso platform token");
    return submitTursoKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyTursoAuth(ctx);
  },
};

async function submitTursoKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("turso auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "TURSO_PLATFORM_TOKEN", token };
  await verifyTursoAuth(ctx);
  const path = writeStoredCredential("turso", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyTursoAuth(ctx: AuthContext): Promise<void> {
  const res = await request(TURSO_AUTH_VALIDATE_URL, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`turso verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`turso verify failed: ${res.status}`);
  }
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
