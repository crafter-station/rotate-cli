import type { PromptAnswers, PromptIO, PromptStep } from "./types.ts";

export async function runPromptFlow(io: PromptIO, steps: PromptStep[]): Promise<PromptAnswers> {
  const answers: PromptAnswers = {};
  for (const step of steps) {
    switch (step.kind) {
      case "note":
        io.note(step.message);
        break;
      case "text":
        answers[step.name] = (await io.promptLine(step.message)).trim();
        break;
      case "password":
        answers[step.name] = (await io.promptSecret(step.message)).trim();
        break;
      case "select":
        answers[step.name] = await io.select(step.message, step.choices);
        break;
      case "confirm":
        answers[step.name] = await io.confirm(step.message, { initialValue: step.initialValue });
        break;
      default:
        step satisfies never;
    }
  }
  return answers;
}
