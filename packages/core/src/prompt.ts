import { stderr, stdin } from "node:process";
import { createClackPromptIO } from "./prompt-runtime.ts";
import type { PromptIO } from "./types.ts";

class NonInteractivePromptIO implements PromptIO {
  readonly isInteractive = false;

  note(message: string): void {
    stderr.write(`${message}\n`);
  }

  async promptLine(): Promise<string> {
    throw new Error("prompt unavailable: interactive terminal required");
  }

  async promptSecret(): Promise<string> {
    throw new Error("prompt unavailable: interactive terminal required");
  }

  async select(): Promise<string> {
    throw new Error("prompt unavailable: interactive terminal required");
  }

  async confirm(): Promise<boolean> {
    throw new Error("prompt unavailable: interactive terminal required");
  }

  async close(): Promise<void> {}
}

export function createPromptIO(): PromptIO {
  if (stdin.isTTY && stderr.isTTY) {
    return createClackPromptIO();
  }
  return new NonInteractivePromptIO();
}
