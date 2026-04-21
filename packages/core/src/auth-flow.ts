import type { AuthContext, AuthDefinition, AuthMethodDefinition, PromptIO } from "./types.ts";
import { runPromptFlow } from "./prompt-flow.ts";

export async function runAuthLoginFlow(definition: AuthDefinition, io: PromptIO): Promise<AuthContext> {
  if (!definition.methods?.length) {
    return definition.login(io);
  }

  const method = await selectAuthMethod(definition, io);
  const answers = await runPromptFlow(io, method.steps);
  return method.submit(answers, io);
}

async function selectAuthMethod(
  definition: AuthDefinition,
  io: PromptIO,
): Promise<AuthMethodDefinition> {
  const methods = definition.methods ?? [];
  if (methods.length === 1) {
    return methods[0]!;
  }

  const selected = await io.select(
    `Choose how to authenticate with ${definition.displayName}`,
    methods.map((method) => ({
      label: method.label,
      value: method.id,
      hint: method.description,
    })),
  );

  const method = methods.find((entry) => entry.id === selected);
  if (!method) {
    throw new Error(`unknown auth method selected: ${selected}`);
  }
  return method;
}
