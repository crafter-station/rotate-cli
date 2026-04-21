import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { makeError } from "@rotate/core";
import type {
  AuthContext,
  Consumer,
  ConsumerTarget,
  RotationResult,
  Secret,
} from "@rotate/core/types";

const PROVIDER = "local-env";

export const localEnvConsumer: Consumer = {
  name: PROVIDER,

  async auth(): Promise<AuthContext> {
    return { kind: "env", varName: "LOCAL_ENV_FILE_ACCESS", token: "local" };
  },

  async propagate(
    target: ConsumerTarget,
    secret: Secret,
    ctx: AuthContext,
  ): Promise<RotationResult<void>> {
    void ctx;
    const spec = resolveTarget(target);
    if (!spec.ok || !spec.data) return { ok: false, error: spec.error };

    try {
      const current = await readEnvFile(spec.data.path);
      const next = upsertEnvValue(current.content, spec.data.varName, secret.value);
      await writeAtomic(spec.data.path, next);
      return { ok: true, data: undefined };
    } catch (cause) {
      return {
        ok: false,
        error: makeError(
          "provider_error",
          `local propagate failed: ${errorMessage(cause)}`,
          PROVIDER,
          {
            cause,
            retryable: false,
          },
        ),
      };
    }
  },

  async verify(
    target: ConsumerTarget,
    secret: Secret,
    ctx: AuthContext,
  ): Promise<RotationResult<boolean>> {
    void ctx;
    const spec = resolveTarget(target);
    if (!spec.ok || !spec.data) return { ok: false, error: spec.error };

    try {
      const current = await readEnvFile(spec.data.path);
      return { ok: true, data: readEnvValue(current.content, spec.data.varName) === secret.value };
    } catch (cause) {
      return {
        ok: false,
        error: makeError(
          "provider_error",
          `local verify failed: ${errorMessage(cause)}`,
          PROVIDER,
          {
            cause,
            retryable: false,
          },
        ),
      };
    }
  },
};

export default localEnvConsumer;

interface ResolvedTarget {
  path: string;
  varName: string;
}

interface EnvFile {
  content: string;
}

function resolveTarget(target: ConsumerTarget): RotationResult<ResolvedTarget> {
  const path = target.params.path;
  const varName = target.params.var_name;
  if (!path || !varName) {
    return {
      ok: false,
      error: makeError("invalid_spec", "params.path and params.var_name required", PROVIDER),
    };
  }
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(varName)) {
    return {
      ok: false,
      error: makeError("invalid_spec", `invalid env var name: ${varName}`, PROVIDER),
    };
  }
  const expanded = expandHome(path);
  if (!isAbsolute(expanded)) {
    return {
      ok: false,
      error: makeError("invalid_spec", "params.path must be absolute or start with ~", PROVIDER),
    };
  }
  return { ok: true, data: { path: expanded, varName } };
}

async function readEnvFile(path: string): Promise<EnvFile> {
  try {
    return { content: await readFile(path, "utf8") };
  } catch (cause) {
    if (isNotFound(cause)) return { content: "" };
    throw cause;
  }
}

async function writeAtomic(path: string, content: string): Promise<void> {
  const directory = dirname(path);
  await mkdir(directory, { recursive: true });
  const tmpPath = join(directory, `.${Date.now()}-${Math.random().toString(16).slice(2)}.tmp`);
  await writeFile(tmpPath, content, { mode: 0o600 });
  await rename(tmpPath, path);
}

function upsertEnvValue(content: string, varName: string, value: string): string {
  const lines = splitLines(content);
  const encoded = encodeEnvValue(value);
  let replaced = false;
  const next = lines.map((line) => {
    const parsed = parseEnvLine(line.text);
    if (!parsed || parsed.varName !== varName) return line.text;
    replaced = true;
    return `${parsed.prefix}${varName}=${encoded}`;
  });

  if (!replaced) {
    next.push(`${varName}=${encoded}`);
  }

  return joinLines(next, content);
}

function readEnvValue(content: string, varName: string): string | undefined {
  let value: string | undefined;
  for (const line of splitLines(content)) {
    const parsed = parseEnvLine(line.text);
    if (parsed?.varName === varName) value = parsed.value;
  }
  return value;
}

function parseEnvLine(line: string): { prefix: string; varName: string; value: string } | null {
  const match = /^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
  if (!match) return null;
  const prefix = match[1] ?? "";
  const varName = match[2];
  const rawValue = match[3] ?? "";
  if (!varName) return null;
  return { prefix, varName, value: decodeEnvValue(rawValue) };
}

function decodeEnvValue(rawValue: string): string {
  const trimmed = rawValue.trim();
  if (trimmed.startsWith('"')) return decodeDoubleQuoted(trimmed);
  if (trimmed.startsWith("'")) return decodeSingleQuoted(trimmed);
  return stripInlineComment(trimmed);
}

function decodeDoubleQuoted(value: string): string {
  let result = "";
  for (let index = 1; index < value.length; index += 1) {
    const char = value[index];
    if (char === '"') break;
    if (char === "\\" && index + 1 < value.length) {
      index += 1;
      const escaped = value[index];
      if (escaped === "n") result += "\n";
      else if (escaped === "r") result += "\r";
      else if (escaped === "t") result += "\t";
      else result += escaped ?? "";
    } else {
      result += char ?? "";
    }
  }
  return result;
}

function decodeSingleQuoted(value: string): string {
  const end = value.indexOf("'", 1);
  return end === -1 ? value.slice(1) : value.slice(1, end);
}

function stripInlineComment(value: string): string {
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === "#" && (index === 0 || /\s/.test(value[index - 1] ?? ""))) {
      return value.slice(0, index).trimEnd();
    }
  }
  return value;
}

function encodeEnvValue(value: string): string {
  return `"${value
    .replaceAll("\\", "\\\\")
    .replaceAll("\n", "\\n")
    .replaceAll("\r", "\\r")
    .replaceAll("\t", "\\t")
    .replaceAll('"', '\\"')}"`;
}

function splitLines(content: string): Array<{ text: string }> {
  if (content.length === 0) return [];
  const lines = content.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  if (content.endsWith("\n")) lines.pop();
  return lines.map((text) => ({ text }));
}

function joinLines(lines: string[], original: string): string {
  if (lines.length === 0) return "";
  const joined = lines.join("\n");
  return original.endsWith("\n") || !joined.endsWith("\n") ? `${joined}\n` : joined;
}

function expandHome(path: string): string {
  if (path === "~") return homedir();
  if (path.startsWith("~/")) return join(homedir(), path.slice(2));
  return path;
}

function isNotFound(cause: unknown): boolean {
  return (
    typeof cause === "object" &&
    cause !== null &&
    "code" in cause &&
    (cause as { code?: string }).code === "ENOENT"
  );
}

function errorMessage(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}
