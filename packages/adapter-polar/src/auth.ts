import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const POLAR_USERS_ME_URL = process.env.POLAR_USERS_ME_URL ?? "https://api.polar.sh/v1/users/me";

export const polarAuthDefinition: AuthDefinition = {
  name: "polar",
  displayName: "Polar",
  envVars: ["POLAR_BOOTSTRAP_TOKEN"],
  setupUrl: "https://polar.sh/dashboard",
  notes: [
    "Organization Access Token (polar_oat_*) with scopes: organization_access_tokens:write + webhooks:write.",
  ],
  methods: [
    {
      id: "paste-oat-key",
      label: "Paste Polar OAT (with write scopes)",
      description: "Create an Organization Access Token in Polar and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "Polar dashboard: https://polar.sh/dashboard\nCreate an Organization Access Token (polar_oat_*) with organization_access_tokens:write + webhooks:write scopes, then paste it below.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste Polar OAT (with write scopes)",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitPolarKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.POLAR_BOOTSTRAP_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "POLAR_BOOTSTRAP_TOKEN", token: envToken };
    }
    const stored = readStoredAuthContext("polar");
    if (stored) return stored;
    throw new Error(
      "polar auth unavailable: set POLAR_BOOTSTRAP_TOKEN or run `rotate auth login polar`",
    );
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste Polar OAT (with write scopes)");
    return submitPolarKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyPolarAuth(ctx);
  },
};

async function submitPolarKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("polar auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "POLAR_BOOTSTRAP_TOKEN", token };
  await verifyPolarAuth(ctx);
  const path = writeStoredCredential("polar", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyPolarAuth(ctx: AuthContext): Promise<void> {
  const res = await request(POLAR_USERS_ME_URL, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`polar verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`polar verify failed: ${res.status}`);
  }
}

function authHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
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
