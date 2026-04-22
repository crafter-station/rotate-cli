import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const FIRECRAWL_BASE = process.env.FIRECRAWL_API_URL ?? "https://api.firecrawl.dev";
const FIRECRAWL_CREDIT_USAGE_URL = `${FIRECRAWL_BASE}/v2/team/credit-usage`;

export const firecrawlAuthDefinition: AuthDefinition = {
  name: "firecrawl",
  displayName: "Firecrawl",
  envVars: ["FIRECRAWL_API_KEY"],
  setupUrl: "https://www.firecrawl.dev/app/api-keys",
  notes: [
    "Uses FIRECRAWL_API_KEY for authenticated liveness checks.",
    "Firecrawl does not document public API key create, list, delete, or introspection endpoints.",
  ],
  methods: [
    {
      id: "paste-api-key",
      label: "Paste Firecrawl API key",
      description: "Create or reveal a Firecrawl API key in the dashboard and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "Firecrawl API keys: https://www.firecrawl.dev/app/api-keys\nCreate or reveal an API key in the Firecrawl dashboard, then paste it below.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste Firecrawl API key",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitFirecrawlKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.FIRECRAWL_API_KEY;
    if (envToken) {
      return { kind: "env", varName: "FIRECRAWL_API_KEY", token: envToken };
    }
    const stored = readStoredAuthContext("firecrawl");
    if (stored) return stored;
    throw new Error(
      "firecrawl auth unavailable: set FIRECRAWL_API_KEY or run `rotate auth login firecrawl`",
    );
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste Firecrawl API key");
    return submitFirecrawlKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyFirecrawlAuth(ctx);
  },
};

async function submitFirecrawlKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("firecrawl auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "FIRECRAWL_API_KEY", token };
  await verifyFirecrawlAuth(ctx);
  const path = writeStoredCredential("firecrawl", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyFirecrawlAuth(ctx: AuthContext): Promise<void> {
  const res = await request(FIRECRAWL_CREDIT_USAGE_URL, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`firecrawl verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`firecrawl verify failed: ${res.status}`);
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
