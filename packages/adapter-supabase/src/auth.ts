import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const SUPABASE_PROJECTS_URL =
  process.env.SUPABASE_PROJECTS_URL ?? "https://api.supabase.com/v1/projects";

export const supabaseAuthDefinition: AuthDefinition = {
  name: "supabase",
  displayName: "Supabase",
  envVars: ["SUPABASE_ACCESS_TOKEN"],
  setupUrl: "https://supabase.com/dashboard/account/tokens",
  notes: ["Personal access token (sbp_*). Not a project service-role key."],
  methods: [
    {
      id: "paste-personal-access-token-key",
      label: "Paste Supabase personal access token",
      description: "Create a personal access token in Supabase and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "Supabase personal access tokens: https://supabase.com/dashboard/account/tokens\nCreate a personal access token (sbp_*), not a project service-role key, then paste it below.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste Supabase personal access token",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitSupabaseKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.SUPABASE_ACCESS_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "SUPABASE_ACCESS_TOKEN", token: envToken };
    }
    const stored = readStoredAuthContext("supabase");
    if (stored) return stored;
    throw new Error(
      "supabase auth unavailable: set SUPABASE_ACCESS_TOKEN or run `rotate auth login supabase`",
    );
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste Supabase personal access token");
    return submitSupabaseKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifySupabaseAuth(ctx);
  },
};

async function submitSupabaseKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("supabase auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "SUPABASE_ACCESS_TOKEN", token };
  await verifySupabaseAuth(ctx);
  const path = writeStoredCredential("supabase", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifySupabaseAuth(ctx: AuthContext): Promise<void> {
  const res = await request(SUPABASE_PROJECTS_URL, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`supabase verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`supabase verify failed: ${res.status}`);
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
