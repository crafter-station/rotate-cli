import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { makeError } from "@rotate/core";
import type {
  AuthContext,
  Consumer,
  ConsumerTarget,
  RotationResult,
  Secret,
} from "@rotate/core/types";
import nacl from "tweetnacl";
import { decodeBase64, decodeUTF8, encodeBase64 } from "tweetnacl-util";

const GITHUB_BASE = process.env.GITHUB_API_URL ?? "https://api.github.com";
const PROVIDER = "github-actions";

export const githubActionsConsumer: Consumer = {
  name: PROVIDER,

  async auth(): Promise<AuthContext> {
    const cliToken = readGhToken();
    if (cliToken) {
      return {
        kind: "cli-piggyback",
        tool: "gh",
        tokenPath: candidateAuthPaths().find((path) => existsSync(path)),
        token: cliToken,
      };
    }
    const envToken = process.env.GITHUB_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "GITHUB_TOKEN", token: envToken };
    }
    throw new Error("github auth unavailable: run `gh auth login` or set GITHUB_TOKEN");
  },

  async propagate(
    target: ConsumerTarget,
    secret: Secret,
    ctx: AuthContext,
  ): Promise<RotationResult<void>> {
    const params = parseTarget(target);
    if (!params.ok || !params.data) {
      return { ok: false, error: params.error };
    }
    const { repo, secretName } = params.data;

    const deleted = await safeFetch(secretUrl(repo, secretName), {
      method: "DELETE",
      headers: authHeaders(ctx),
    });
    if (!deleted.ok) return { ok: false, error: deleted.error };
    const deleteResponse = deleted.data;
    if (!deleteResponse) {
      return {
        ok: false,
        error: makeError("network_error", "github delete: no response", PROVIDER),
      };
    }
    if (!deleteResponse.ok && deleteResponse.status !== 404) {
      return { ok: false, error: fromResponse(deleteResponse, "delete") };
    }

    const publicKey = await safeFetch(publicKeyUrl(repo), {
      headers: authHeaders(ctx),
    });
    if (!publicKey.ok) return { ok: false, error: publicKey.error };
    const publicKeyResponse = publicKey.data;
    if (!publicKeyResponse) {
      return {
        ok: false,
        error: makeError("network_error", "github public-key: no response", PROVIDER),
      };
    }
    if (!publicKeyResponse.ok) {
      return { ok: false, error: fromResponse(publicKeyResponse, "public-key") };
    }

    const key = (await publicKeyResponse.json()) as GitHubPublicKey;
    const encryptedValue = tryEncryptSecret(secret.value, key);
    if (!encryptedValue.ok || !encryptedValue.data) {
      return { ok: false, error: encryptedValue.error };
    }
    const res = await safeFetch(secretUrl(repo, secretName), {
      method: "PUT",
      headers: authHeaders(ctx),
      body: JSON.stringify({ encrypted_value: encryptedValue.data, key_id: key.key_id }),
    });
    if (!res.ok) return { ok: false, error: res.error };
    const response = res.data;
    if (!response) {
      return {
        ok: false,
        error: makeError("network_error", "github propagate: no response", PROVIDER),
      };
    }
    if (!response.ok) return { ok: false, error: fromResponse(response, "propagate") };
    return { ok: true, data: undefined };
  },

  async verify(
    target: ConsumerTarget,
    secret: Secret,
    ctx: AuthContext,
  ): Promise<RotationResult<boolean>> {
    const params = parseTarget(target);
    if (!params.ok || !params.data) {
      return { ok: false, error: params.error };
    }
    const { repo, secretName } = params.data;

    const res = await safeFetch(secretUrl(repo, secretName), {
      headers: authHeaders(ctx),
    });
    if (!res.ok) return { ok: false, error: res.error };
    const response = res.data;
    if (!response) {
      return {
        ok: false,
        error: makeError("network_error", "github verify: no response", PROVIDER),
      };
    }
    if (response.status === 404) return { ok: true, data: false };
    if (!response.ok) return { ok: false, error: fromResponse(response, "verify") };

    const data = (await response.json()) as GitHubSecretMetadata;
    if (!data.updated_at) return { ok: true, data: true };
    const updated = new Date(data.updated_at).getTime();
    const created = new Date(secret.createdAt).getTime();
    return { ok: true, data: updated >= created - 5_000 };
  },
};

export default githubActionsConsumer;

interface GitHubPublicKey {
  key_id: string;
  key: string;
}

interface GitHubSecretMetadata {
  updated_at?: string;
}

interface TargetParams {
  repo: string;
  secretName: string;
}

function parseTarget(target: ConsumerTarget): RotationResult<TargetParams> {
  const repo = target.params.repo;
  const secretName = target.params.secret_name;
  if (!repo || !secretName) {
    return {
      ok: false,
      error: makeError("invalid_spec", "params.repo and params.secret_name required", PROVIDER),
    };
  }
  if (!/^[^/\s]+\/[^/\s]+$/.test(repo)) {
    return {
      ok: false,
      error: makeError("invalid_spec", "params.repo must be owner/name", PROVIDER),
    };
  }
  return { ok: true, data: { repo, secretName } };
}

function authHeaders(ctx: AuthContext): Record<string, string> {
  return {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${ctx.token}`,
    "Content-Type": "application/json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

function publicKeyUrl(repo: string): string {
  return `${GITHUB_BASE}/repos/${repo}/actions/secrets/public-key`;
}

function secretUrl(repo: string, secretName: string): string {
  return `${GITHUB_BASE}/repos/${repo}/actions/secrets/${encodeURIComponent(secretName)}`;
}

function readGhToken(): string | null {
  try {
    const token = execFileSync("gh", ["auth", "token"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return token || null;
  } catch {
    return null;
  }
}

function candidateAuthPaths(): string[] {
  const home = homedir();
  return [
    join(home, ".config", "gh", "hosts.yml"),
    join(home, ".config", "github", "hosts.yml"),
    join(home, ".github", "hosts.yml"),
  ];
}

async function safeFetch(url: string, init?: RequestInit): Promise<RotationResult<Response>> {
  try {
    return { ok: true, data: await fetch(url, init) };
  } catch (cause) {
    return {
      ok: false,
      error: makeError("network_error", "github network error", PROVIDER, { cause }),
    };
  }
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `github ${op}: ${res.status}`, PROVIDER);
  }
  if (res.status === 429) return makeError("rate_limited", `github ${op}: 429`, PROVIDER);
  if (res.status === 404) return makeError("not_found", `github ${op}: 404`, PROVIDER);
  if (res.status >= 500) {
    return makeError("provider_error", `github ${op}: ${res.status}`, PROVIDER);
  }
  return makeError("provider_error", `github ${op}: ${res.status}`, PROVIDER, {
    retryable: false,
  });
}

function encryptSecret(value: string, publicKeyBase64: string): string {
  const publicKey = decodeBase64(publicKeyBase64);
  const ephemeral = nacl.box.keyPair();
  const nonce = blake2b(new Uint8Array([...ephemeral.publicKey, ...publicKey]), 24);
  const boxed = nacl.box(decodeUTF8(value), nonce, publicKey, ephemeral.secretKey);
  return encodeBase64(new Uint8Array([...ephemeral.publicKey, ...boxed]));
}

function tryEncryptSecret(value: string, key: GitHubPublicKey): RotationResult<string> {
  if (!key.key || !key.key_id) {
    return {
      ok: false,
      error: makeError("provider_error", "github public-key: malformed response", PROVIDER, {
        retryable: false,
      }),
    };
  }
  try {
    return { ok: true, data: encryptSecret(value, key.key) };
  } catch (cause) {
    return {
      ok: false,
      error: makeError("provider_error", "github public-key: encryption failed", PROVIDER, {
        cause,
        retryable: false,
      }),
    };
  }
}

const IV = [
  0x6a09e667f3bcc908n,
  0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn,
  0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,
  0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn,
  0x5be0cd19137e2179n,
] as const;
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
] as const;
const MASK_64 = (1n << 64n) - 1n;

function blake2b(input: Uint8Array, outLength: number): Uint8Array {
  const h: bigint[] = [...IV];
  h[0] = h[0]! ^ BigInt(0x01010000 ^ outLength);
  const block = new Uint8Array(128);
  block.set(input);
  compress(h, block, BigInt(input.length), true);
  const out = new Uint8Array(outLength);
  for (let i = 0; i < 8; i++) store64(out, i * 8, h[i]!);
  return out.slice(0, outLength);
}

function compress(h: bigint[], block: Uint8Array, counter: bigint, last: boolean): void {
  const m = Array.from({ length: 16 }, (_, i) => load64(block, i * 8));
  const v = [...h, ...IV];
  v[12] = v[12]! ^ counter;
  if (last) v[14] = v[14]! ^ MASK_64;
  for (let round = 0; round < 12; round++) {
    const s = SIGMA[round]!;
    g(v, 0, 4, 8, 12, m[s[0]!]!, m[s[1]!]!);
    g(v, 1, 5, 9, 13, m[s[2]!]!, m[s[3]!]!);
    g(v, 2, 6, 10, 14, m[s[4]!]!, m[s[5]!]!);
    g(v, 3, 7, 11, 15, m[s[6]!]!, m[s[7]!]!);
    g(v, 0, 5, 10, 15, m[s[8]!]!, m[s[9]!]!);
    g(v, 1, 6, 11, 12, m[s[10]!]!, m[s[11]!]!);
    g(v, 2, 7, 8, 13, m[s[12]!]!, m[s[13]!]!);
    g(v, 3, 4, 9, 14, m[s[14]!]!, m[s[15]!]!);
  }
  for (let i = 0; i < 8; i++) h[i] = (h[i]! ^ v[i]! ^ v[i + 8]!) & MASK_64;
}

function g(v: bigint[], a: number, b: number, c: number, d: number, x: bigint, y: bigint): void {
  v[a] = (v[a]! + v[b]! + x) & MASK_64;
  v[d] = rotr(v[d]! ^ v[a]!, 32n);
  v[c] = (v[c]! + v[d]!) & MASK_64;
  v[b] = rotr(v[b]! ^ v[c]!, 24n);
  v[a] = (v[a]! + v[b]! + y) & MASK_64;
  v[d] = rotr(v[d]! ^ v[a]!, 16n);
  v[c] = (v[c]! + v[d]!) & MASK_64;
  v[b] = rotr(v[b]! ^ v[c]!, 63n);
}

function rotr(value: bigint, bits: bigint): bigint {
  return ((value >> bits) | (value << (64n - bits))) & MASK_64;
}

function load64(input: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let i = 0; i < 8; i++) value |= BigInt(input[offset + i] ?? 0) << BigInt(8 * i);
  return value;
}

function store64(output: Uint8Array, offset: number, value: bigint): void {
  for (let i = 0; i < 8 && offset + i < output.length; i++) {
    output[offset + i] = Number((value >> BigInt(8 * i)) & 0xffn);
  }
}
