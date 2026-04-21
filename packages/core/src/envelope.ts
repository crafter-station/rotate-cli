/** Standard output envelope. See docs/CLI_SPEC.md §Output envelope. */

import type { AdapterError } from "./types.ts";

export type EnvelopeStatus = "success" | "partial" | "error" | "in_progress";

export interface Envelope<T = unknown> {
  version: "1";
  command: string;
  status: EnvelopeStatus;
  data?: T;
  errors: AdapterError[];
  next_actions: string[];
  meta: EnvelopeMeta;
}

export interface EnvelopeMeta {
  timestamp: string;
  duration_ms: number;
  agent_mode: boolean;
}

export interface EnvelopeInput<T> {
  command: string;
  status: EnvelopeStatus;
  data?: T;
  errors?: AdapterError[];
  next_actions?: string[];
  startedAt: number;
  agentMode?: boolean;
}

export function makeEnvelope<T>(input: EnvelopeInput<T>): Envelope<T> {
  return {
    version: "1",
    command: input.command,
    status: input.status,
    data: input.data,
    errors: input.errors ?? [],
    next_actions: input.next_actions ?? [],
    meta: {
      timestamp: new Date().toISOString(),
      duration_ms: Date.now() - input.startedAt,
      agent_mode: input.agentMode ?? false,
    },
  };
}

/** Emit envelope to stdout as JSON. Exits with the given code if provided. */
export function emit<T>(envelope: Envelope<T>, exitCode?: number): void {
  process.stdout.write(`${JSON.stringify(envelope)}\n`);
  if (exitCode !== undefined) process.exit(exitCode);
}

/** JSON Schema for the envelope, used by `rotate schema <command>`. */
export const envelopeJsonSchema = {
  $schema: "http://json-schema.org/draft-07/schema#",
  type: "object",
  required: ["version", "command", "status", "errors", "next_actions", "meta"],
  properties: {
    version: { const: "1" },
    command: { type: "string" },
    status: {
      type: "string",
      enum: ["success", "partial", "error", "in_progress"],
    },
    data: {},
    errors: {
      type: "array",
      items: {
        type: "object",
        required: ["code", "message", "provider", "retryable"],
        properties: {
          code: { type: "string" },
          message: { type: "string" },
          provider: { type: "string" },
          retryable: { type: "boolean" },
        },
      },
    },
    next_actions: { type: "array", items: { type: "string" } },
    meta: {
      type: "object",
      required: ["timestamp", "duration_ms", "agent_mode"],
      properties: {
        timestamp: { type: "string", format: "date-time" },
        duration_ms: { type: "integer", minimum: 0 },
        agent_mode: { type: "boolean" },
      },
    },
  },
} as const;
