import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AuthContext, Secret } from "@rotate/core/types";
import { localEnvConsumer } from "../src/index.ts";

type FetchFn = typeof fetch;

const originalFetch = global.fetch;
let calls: Array<{ url: string; init?: RequestInit }> = [];
let tempDir: string;

function mockFetch(responder: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  global.fetch = ((url: RequestInfo | URL, init?: RequestInit) => {
    const u = typeof url === "string" ? url : url.toString();
    calls.push({ url: u, init });
    return Promise.resolve(responder(u, init));
  }) as FetchFn;
}

beforeEach(async () => {
  calls = [];
  tempDir = await mkdtemp(join(tmpdir(), "rotate-local-env-"));
});

afterEach(async () => {
  global.fetch = originalFetch;
  await rm(tempDir, { recursive: true, force: true });
});

const mockCtx: AuthContext = { kind: "env", varName: "LOCAL_ENV_FILE_ACCESS", token: "local" };
const mockSecret: Secret = {
  id: "key",
  provider: "clerk",
  value: "sk_live_new",
  metadata: {},
  createdAt: new Date().toISOString(),
};

describe("consumer-local-env.propagate", () => {
  test("appends env var when not present", async () => {
    mockFetch(() => new Response("unexpected", { status: 500 }));
    const path = join(tempDir, ".env");
    await writeFile(path, "# app\nOTHER=value\n", "utf8");

    const r = await localEnvConsumer.propagate(
      { type: "local-env", params: { path, var_name: "API_KEY" } },
      mockSecret,
      mockCtx,
    );

    expect(r.ok).toBe(true);
    expect(await readFile(path, "utf8")).toBe('# app\nOTHER=value\nAPI_KEY="sk_live_new"\n');
    expect(calls.length).toBe(0);
  });

  test("deletes existing then recreates", async () => {
    mockFetch(() => new Response("unexpected", { status: 500 }));
    const path = join(tempDir, ".env");
    await writeFile(path, "# app\nAPI_KEY=old\nOTHER=value\n", "utf8");

    const r = await localEnvConsumer.propagate(
      { type: "local-env", params: { path, var_name: "API_KEY" } },
      mockSecret,
      mockCtx,
    );

    expect(r.ok).toBe(true);
    expect(await readFile(path, "utf8")).toBe('# app\nAPI_KEY="sk_live_new"\nOTHER=value\n');
    expect(calls.length).toBe(0);
  });

  test("missing params returns invalid_spec", async () => {
    mockFetch(() => new Response("unexpected", { status: 500 }));

    const r = await localEnvConsumer.propagate(
      { type: "local-env", params: { var_name: "API_KEY" } },
      mockSecret,
      mockCtx,
    );

    expect(r.ok).toBe(false);
    expect(r.error?.code).toBe("invalid_spec");
    expect(calls.length).toBe(0);
  });
});

describe("consumer-local-env.verify", () => {
  test("returns true when var value matches", async () => {
    mockFetch(() => new Response("unexpected", { status: 500 }));
    const path = join(tempDir, ".env");
    await writeFile(path, 'API_KEY="sk_live_new"\n', "utf8");

    const r = await localEnvConsumer.verify?.(
      { type: "local-env", params: { path, var_name: "API_KEY" } },
      mockSecret,
      mockCtx,
    );

    expect(r?.ok).toBe(true);
    expect(r?.data).toBe(true);
    expect(calls.length).toBe(0);
  });

  test("returns false when var value differs", async () => {
    mockFetch(() => new Response("unexpected", { status: 500 }));
    const path = join(tempDir, ".env");
    await writeFile(path, "API_KEY=old\n", "utf8");

    const r = await localEnvConsumer.verify?.(
      { type: "local-env", params: { path, var_name: "API_KEY" } },
      mockSecret,
      mockCtx,
    );

    expect(r?.ok).toBe(true);
    expect(r?.data).toBe(false);
    expect(calls.length).toBe(0);
  });
});
