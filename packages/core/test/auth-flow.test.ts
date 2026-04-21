import { describe, expect, test } from "bun:test";
import { runAuthLoginFlow } from "../src/auth-flow.ts";
import type { AuthDefinition, PromptChoice, PromptConfirmOptions, PromptIO } from "../src/types.ts";

class ScriptedPromptIO implements PromptIO {
  readonly isInteractive = true;

  constructor(
    private readonly values: {
      selects?: string[];
      secrets?: string[];
    },
  ) {}

  note(): void {}

  async promptLine(): Promise<string> {
    return "";
  }

  async promptSecret(): Promise<string> {
    return this.values.secrets?.shift() ?? "";
  }

  async select(_message: string, _choices: PromptChoice[]): Promise<string> {
    return this.values.selects?.shift() ?? "";
  }

  async confirm(_message: string, _options?: PromptConfirmOptions): Promise<boolean> {
    return true;
  }

  async close(): Promise<void> {}
}

describe("runAuthLoginFlow", () => {
  test("runs declarative auth methods", async () => {
    const definition: AuthDefinition = {
      name: "openai",
      displayName: "OpenAI",
      envVars: ["OPENAI_ADMIN_KEY"],
      methods: [
        {
          id: "paste-admin-key",
          label: "Paste admin key",
          steps: [{ kind: "password", name: "token", message: "Token" }],
          async submit(answers) {
            return {
              kind: "env",
              varName: "OPENAI_ADMIN_KEY",
              token: String(answers.token),
            };
          },
        },
      ],
      async resolve() {
        throw new Error("not implemented");
      },
      async login() {
        throw new Error("legacy login should not run");
      },
    };

    const ctx = await runAuthLoginFlow(definition, new ScriptedPromptIO({ secrets: ["sk-admin"] }));
    expect(ctx.kind).toBe("env");
    expect(ctx.token).toBe("sk-admin");
  });

  test("falls back to legacy login when methods are absent", async () => {
    const definition: AuthDefinition = {
      name: "openai",
      displayName: "OpenAI",
      envVars: ["OPENAI_ADMIN_KEY"],
      async resolve() {
        throw new Error("not implemented");
      },
      async login() {
        return {
          kind: "env",
          varName: "OPENAI_ADMIN_KEY",
          token: "legacy",
        };
      },
    };

    const ctx = await runAuthLoginFlow(definition, new ScriptedPromptIO({}));
    expect(ctx.token).toBe("legacy");
  });
});
