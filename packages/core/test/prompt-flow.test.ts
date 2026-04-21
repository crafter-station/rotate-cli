import { describe, expect, test } from "bun:test";
import { runPromptFlow } from "../src/prompt-flow.ts";
import type { PromptChoice, PromptConfirmOptions, PromptIO } from "../src/types.ts";

class ScriptedPromptIO implements PromptIO {
  readonly isInteractive = true;
  notes: string[] = [];

  constructor(
    private readonly values: {
      lines?: string[];
      secrets?: string[];
      selects?: string[];
      confirms?: boolean[];
    },
  ) {}

  note(message: string): void {
    this.notes.push(message);
  }

  async promptLine(_message: string): Promise<string> {
    return this.values.lines?.shift() ?? "";
  }

  async promptSecret(_message: string): Promise<string> {
    return this.values.secrets?.shift() ?? "";
  }

  async select(_message: string, _choices: PromptChoice[]): Promise<string> {
    return this.values.selects?.shift() ?? "";
  }

  async confirm(_message: string, _options?: PromptConfirmOptions): Promise<boolean> {
    return this.values.confirms?.shift() ?? false;
  }

  async close(): Promise<void> {}
}

describe("runPromptFlow", () => {
  test("collects answers across prompt step types", async () => {
    const io = new ScriptedPromptIO({
      lines: ["  hello  "],
      secrets: ["  secret  "],
      selects: ["openai"],
      confirms: [true],
    });

    const answers = await runPromptFlow(io, [
      { kind: "note", message: "start" },
      { kind: "text", name: "label", message: "Label" },
      { kind: "password", name: "token", message: "Token" },
      {
        kind: "select",
        name: "provider",
        message: "Provider",
        choices: [{ label: "OpenAI", value: "openai" }],
      },
      { kind: "confirm", name: "overwrite", message: "Overwrite?" },
    ]);

    expect(io.notes).toEqual(["start"]);
    expect(answers).toEqual({
      label: "hello",
      token: "secret",
      provider: "openai",
      overwrite: true,
    });
  });
});
