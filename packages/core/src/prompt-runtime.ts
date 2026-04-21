import { stderr } from "node:process";
import * as prompts from "@clack/prompts";
import type { PromptChoice, PromptConfirmOptions, PromptIO } from "./types.ts";

function isCancelled(value: unknown): boolean {
  return prompts.isCancel(value);
}

function assertPromptValue<T>(value: T | symbol | undefined): T {
  if (value === undefined || isCancelled(value)) {
    throw new Error("prompt cancelled");
  }
  return value as T;
}

export class ClackPromptIO implements PromptIO {
  readonly isInteractive = true;

  note(message: string): void {
    for (const line of message.split("\n")) {
      stderr.write(`${line}\n`);
    }
  }

  async promptLine(message: string): Promise<string> {
    const result = await prompts.text({
      message,
      validate(value) {
        return String(value ?? "").trim() ? undefined : "This value is required";
      },
    });
    return assertPromptValue(result);
  }

  async promptSecret(message: string): Promise<string> {
    const result = await prompts.password({
      message,
      mask: "*",
      validate(value) {
        return String(value ?? "").trim() ? undefined : "This value is required";
      },
    });
    return assertPromptValue(result);
  }

  async select(message: string, choices: PromptChoice[]): Promise<string> {
    if (!choices.length) throw new Error("prompt select requires at least one choice");
    const result = await prompts.select({
      message,
      options: choices.map((choice) => ({
        label: choice.label,
        value: choice.value,
        hint: choice.hint,
      })),
    });
    return assertPromptValue(result);
  }

  async confirm(message: string, options: PromptConfirmOptions = {}): Promise<boolean> {
    const result = await prompts.confirm({
      message,
      initialValue: options.initialValue ?? true,
    });
    return assertPromptValue(result);
  }

  async close(): Promise<void> {
    stderr.write("");
  }
}

export function createClackPromptIO(): PromptIO {
  return new ClackPromptIO();
}
