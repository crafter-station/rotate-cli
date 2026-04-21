import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { RotateError, makeError } from "./errors.ts";
import type { IncidentFile, RotateConfig } from "./types.ts";

const consumerTargetSchema = z.object({
  type: z.string().min(1),
  params: z.record(z.string(), z.string()),
});

const secretConfigSchema = z.object({
  id: z.string().min(1),
  adapter: z.string().min(1),
  metadata: z.record(z.string(), z.string()).optional(),
  tags: z.array(z.string()).optional(),
  consumers: z.array(consumerTargetSchema).default([]),
});

const rotateConfigSchema = z.object({
  version: z.literal(1),
  defaults: z
    .object({
      grace_period_floor: z.string().optional(),
    })
    .optional(),
  secrets: z.array(secretConfigSchema).default([]),
});

const incidentScopeSchema = z.object({
  provider: z.string().min(1),
  filter: z.record(z.string(), z.string()).optional(),
});

const incidentFileSchema = z.object({
  version: z.literal(1),
  id: z.string().min(1),
  published: z.string().optional(),
  reference: z.string().optional(),
  severity: z.enum(["low", "medium", "high", "critical"]).optional(),
  scope: z.array(incidentScopeSchema).min(1),
});

export function loadConfig(path = "./rotate.config.yaml"): RotateConfig {
  const abs = resolve(process.cwd(), path);
  let raw: string;
  try {
    raw = readFileSync(abs, "utf8");
  } catch (cause) {
    throw new RotateError(
      makeError("invalid_spec", `config not found at ${abs}`, "rotate-cli", { cause }),
      1,
    );
  }
  const parsed = parseYaml(raw);
  const result = rotateConfigSchema.safeParse(parsed);
  if (!result.success) {
    throw new RotateError(
      makeError("invalid_spec", `config invalid: ${result.error.message}`, "rotate-cli"),
      1,
    );
  }
  return result.data as RotateConfig;
}

export function loadIncident(path: string): IncidentFile {
  const abs = resolve(process.cwd(), path);
  const raw = readFileSync(abs, "utf8");
  const parsed = parseYaml(raw);
  const result = incidentFileSchema.safeParse(parsed);
  if (!result.success) {
    throw new RotateError(
      makeError("invalid_spec", `incident invalid: ${result.error.message}`, "rotate-cli"),
      1,
    );
  }
  return result.data as IncidentFile;
}

/** Select config secrets that match an incident scope (intersection). */
export function selectByIncident(config: RotateConfig, incident: IncidentFile) {
  return config.secrets.filter((secret) =>
    incident.scope.some((scope) => {
      if (scope.provider !== secret.adapter) return false;
      if (!scope.filter) return true;
      return Object.entries(scope.filter).every(([key, value]) => {
        if (key === "tag") return secret.tags?.includes(value) ?? false;
        return secret.metadata?.[key] === value;
      });
    }),
  );
}

/** Select by identifier ("provider/id") or query flags. */
export function selectByQuery(
  config: RotateConfig,
  query: { ids?: string[]; provider?: string; tag?: string },
) {
  return config.secrets.filter((secret) => {
    if (query.ids?.length) {
      const canonical = `${secret.adapter}/${secret.id}`;
      if (!query.ids.includes(secret.id) && !query.ids.includes(canonical)) return false;
    }
    if (query.provider && secret.adapter !== query.provider) return false;
    if (query.tag && !secret.tags?.includes(query.tag)) return false;
    return true;
  });
}

export function parseDuration(input: string): number {
  const match = /^(\d+)(ms|s|m|h|d)$/.exec(input.trim());
  if (!match) throw new Error(`invalid duration: ${input}`);
  const n = Number(match[1]);
  switch (match[2]) {
    case "ms":
      return n;
    case "s":
      return n * 1_000;
    case "m":
      return n * 60_000;
    case "h":
      return n * 3_600_000;
    case "d":
      return n * 86_400_000;
    default:
      throw new Error(`invalid duration: ${input}`);
  }
}
