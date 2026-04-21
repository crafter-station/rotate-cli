import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { makeError } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

type CreateEndpoint = string | ((spec: RotationSpec) => string);
type SecretEndpoint = string | ((secret: Secret) => string);

export interface RestAdapterSpec<TCreateResponse = unknown> {
  name: string;
  baseUrl: string;
  authEnvVar: string;
  createEndpoint: CreateEndpoint;
  verifyEndpoint: SecretEndpoint;
  revokeEndpoint: SecretEndpoint;
  responseMapper: (body: TCreateResponse, spec: RotationSpec) => Secret;
}

export function defineRestAdapter<TCreateResponse = unknown>(
  spec: RestAdapterSpec<TCreateResponse>,
): Adapter {
  return {
    name: spec.name,

    async auth(): Promise<AuthContext> {
      for (const path of candidateAuthPaths(spec.name)) {
        if (!existsSync(path)) continue;
        const token = readTokenFile(path);
        if (token) {
          return { kind: "cli-piggyback", tool: spec.name, tokenPath: path, token };
        }
      }

      const envToken = process.env[spec.authEnvVar];
      if (envToken) {
        return { kind: "env", varName: spec.authEnvVar, token: envToken };
      }

      throw new Error(
        `${spec.name} auth unavailable: run \`${spec.name} login\` or set ${spec.authEnvVar}`,
      );
    },

    async create(rotation: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
      const res = await request(urlFor(spec.baseUrl, resolveCreateEndpoint(spec, rotation)), {
        method: "POST",
        headers: authHeaders(ctx.token),
        body: JSON.stringify({
          secretId: rotation.secretId,
          metadata: rotation.metadata,
          reason: rotation.reason,
        }),
      });
      if (res instanceof Error) return { ok: false, error: networkError(spec.name, res) };
      if (!res.ok) return { ok: false, error: fromResponse(spec.name, res, "create") };

      const body = await parseJson<TCreateResponse>(res);
      if (body instanceof Error) {
        return {
          ok: false,
          error: makeError(
            "provider_error",
            `${spec.name} create: invalid JSON response`,
            spec.name,
            { retryable: false, cause: body },
          ),
        };
      }

      const secret = spec.responseMapper(body, rotation);
      const validation = validateSecret(spec.name, secret);
      if (validation) return { ok: false, error: validation };
      return { ok: true, data: secret };
    },

    async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
      const res = await request(
        urlFor(spec.baseUrl, resolveSecretEndpoint(spec.verifyEndpoint, secret)),
        {
          headers: authHeaders(secret.value),
        },
      );
      if (res instanceof Error) return { ok: false, error: networkError(spec.name, res) };
      if (!res.ok) return { ok: false, error: fromResponse(spec.name, res, "verify") };
      return { ok: true, data: true };
    },

    async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
      const res = await request(
        urlFor(spec.baseUrl, resolveSecretEndpoint(spec.revokeEndpoint, secret)),
        {
          method: "DELETE",
          headers: authHeaders(ctx.token),
        },
      );
      if (res instanceof Error) return { ok: false, error: networkError(spec.name, res) };
      if (res.status === 404) return { ok: true, data: undefined };
      if (!res.ok) return { ok: false, error: fromResponse(spec.name, res, "revoke") };
      return { ok: true, data: undefined };
    },
  };
}

function authHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

async function request(url: string, init: RequestInit): Promise<Response | Error> {
  try {
    return await fetch(url, init);
  } catch (cause) {
    return cause instanceof Error ? cause : new Error(String(cause));
  }
}

async function parseJson<T>(res: Response): Promise<T | Error> {
  try {
    return (await res.json()) as T;
  } catch (cause) {
    return cause instanceof Error ? cause : new Error(String(cause));
  }
}

function resolveCreateEndpoint<TCreateResponse>(
  spec: RestAdapterSpec<TCreateResponse>,
  rotation: RotationSpec,
): string {
  return typeof spec.createEndpoint === "function"
    ? spec.createEndpoint(rotation)
    : spec.createEndpoint;
}

function resolveSecretEndpoint(endpoint: SecretEndpoint, secret: Secret): string {
  return typeof endpoint === "function" ? endpoint(secret) : endpoint;
}

function urlFor(baseUrl: string, endpoint: string): string {
  if (/^https?:\/\//.test(endpoint)) return endpoint;
  return `${baseUrl.replace(/\/$/, "")}/${endpoint.replace(/^\//, "")}`;
}

function candidateAuthPaths(name: string): string[] {
  const home = homedir();
  return [
    join(home, `.${name}`, "auth.json"),
    join(home, `.${name}`, "config.json"),
    join(home, ".config", name, "auth.json"),
    join(home, ".config", name, "config.json"),
  ];
}

function readTokenFile(path: string): string | null {
  try {
    const data = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    for (const key of ["token", "access_token", "apiKey", "api_key"]) {
      const value = data[key];
      if (typeof value === "string" && value.length > 0) return value;
    }
  } catch {
    return null;
  }
  return null;
}

function validateSecret(provider: string, secret: Secret) {
  if (
    !secret.id ||
    !secret.provider ||
    !secret.value ||
    !secret.createdAt ||
    typeof secret.metadata !== "object" ||
    secret.metadata === null
  ) {
    return makeError(
      "provider_error",
      `${provider} create: response mapper returned invalid Secret`,
      provider,
      {
        retryable: false,
      },
    );
  }
  return null;
}

function networkError(provider: string, cause: Error) {
  return makeError("network_error", `${provider} network error: ${cause.message}`, provider, {
    cause,
  });
}

function fromResponse(provider: string, res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `${provider} ${op}: ${res.status}`, provider);
  }
  if (res.status === 429) return makeError("rate_limited", `${provider} ${op}: 429`, provider);
  if (res.status === 404) return makeError("not_found", `${provider} ${op}: 404`, provider);
  if (res.status >= 500) {
    return makeError("provider_error", `${provider} ${op}: ${res.status}`, provider);
  }
  return makeError("provider_error", `${provider} ${op}: ${res.status}`, provider, {
    retryable: false,
  });
}
