import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const UPLOADTHING_VERIFY_URL =
  process.env.UPLOADTHING_VERIFY_URL ?? "https://api.uploadthing.com/v6/listFiles";

export const uploadthingAuthDefinition: AuthDefinition = {
  name: "uploadthing",
  displayName: "UploadThing",
  envVars: ["UPLOADTHING_TOKEN", "UPLOADTHING_SECRET", "UPLOADTHING_APP_ID"],
  setupUrl: "https://uploadthing.com/dashboard",
  notes: [
    "Uses UPLOADTHING_TOKEN when available, with legacy UPLOADTHING_SECRET plus UPLOADTHING_APP_ID supported for existing apps.",
    "UploadThing key rotation is dashboard-only; rotate-cli guides the manual create and revoke steps.",
  ],
  methods: [
    {
      id: "paste-token",
      label: "Paste UploadThing token",
      description: "Create or copy a token in the UploadThing dashboard and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "UploadThing dashboard: https://uploadthing.com/dashboard\nCreate or copy a server token for the target app, then paste it below.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste UploadThing token or legacy secret",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitUploadthingToken(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.UPLOADTHING_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "UPLOADTHING_TOKEN", token: envToken };
    }

    const legacySecret = process.env.UPLOADTHING_SECRET;
    if (legacySecret) {
      return { kind: "env", varName: "UPLOADTHING_SECRET", token: legacySecret };
    }

    const stored = readStoredAuthContext("uploadthing");
    if (stored) return stored;
    throw new Error(
      "uploadthing auth unavailable: set UPLOADTHING_TOKEN or run `rotate auth login uploadthing`",
    );
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste UploadThing token or legacy secret");
    return submitUploadthingToken(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyUploadthingAuth(ctx);
  },
};

async function submitUploadthingToken(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("uploadthing auth unavailable: pasted token was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "UPLOADTHING_TOKEN", token };
  await verifyUploadthingAuth(ctx);
  const path = writeStoredCredential("uploadthing", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyUploadthingAuth(ctx: AuthContext): Promise<void> {
  const res = await request(UPLOADTHING_VERIFY_URL, {
    method: "GET",
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`uploadthing verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`uploadthing verify failed: ${res.status}`);
  }
}

function authHeaders(token: string): Record<string, string> {
  return {
    "Content-Type": "application/json",
    "User-Agent": "rotate-cli/0.0.1",
    "x-api-key": token,
  };
}

async function request(url: string, init: RequestInit): Promise<Response | Error> {
  try {
    return await fetch(url, init);
  } catch (cause) {
    return cause instanceof Error ? cause : new Error(String(cause));
  }
}
