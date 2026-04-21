import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { AuthContext, Secret } from "@rotate/core/types";
import { vercelEnvConsumer } from "../src/index.ts";

type FetchFn = typeof fetch;
const originalFetch = global.fetch;
let calls: Array<{ url: string; init?: RequestInit }> = [];

function mockFetch(responder: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  global.fetch = ((url: RequestInfo | URL, init?: RequestInit) => {
    const u = typeof url === "string" ? url : url.toString();
    calls.push({ url: u, init });
    return Promise.resolve(responder(u, init));
  }) as FetchFn;
}

beforeEach(() => {
  calls = [];
});

afterEach(() => {
  global.fetch = originalFetch;
});

const mockCtx: AuthContext = { kind: "env", varName: "VERCEL_TOKEN", token: "verc_test" };
const mockSecret: Secret = {
  id: "key",
  provider: "clerk",
  value: "sk_live_new",
  metadata: {},
  createdAt: new Date().toISOString(),
};

describe("consumer-vercel-env.propagate", () => {
  test("creates env var when not present", async () => {
    mockFetch((url, init) => {
      if (url.includes("/v9/projects/") && url.includes("/env") && init?.method !== "DELETE") {
        return new Response(JSON.stringify({ envs: [] }), { status: 200 });
      }
      if (url.includes("/v10/projects/") && init?.method === "POST") {
        return new Response(JSON.stringify({ ok: true }), { status: 201 });
      }
      return new Response("unexpected", { status: 500 });
    });
    const r = await vercelEnvConsumer.propagate(
      { type: "vercel-env", params: { project: "hack0", var_name: "API_KEY" } },
      mockSecret,
      mockCtx,
    );
    expect(r.ok).toBe(true);
    expect(calls.some((c) => c.url.includes("/v10/projects/hack0/env"))).toBe(true);
  });

  test("deletes existing then recreates", async () => {
    let deleteCalled = false;
    mockFetch((url, init) => {
      if (url.includes("/v9/projects/") && init?.method !== "DELETE") {
        return new Response(JSON.stringify({ envs: [{ id: "env_old", key: "API_KEY" }] }), {
          status: 200,
        });
      }
      if (init?.method === "DELETE") {
        deleteCalled = true;
        return new Response("", { status: 200 });
      }
      if (url.includes("/v10/projects/") && init?.method === "POST") {
        return new Response(JSON.stringify({ ok: true }), { status: 201 });
      }
      return new Response("unexpected", { status: 500 });
    });
    const r = await vercelEnvConsumer.propagate(
      { type: "vercel-env", params: { project: "hack0", var_name: "API_KEY" } },
      mockSecret,
      mockCtx,
    );
    expect(r.ok).toBe(true);
    expect(deleteCalled).toBe(true);
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const r = await vercelEnvConsumer.propagate(
      { type: "vercel-env", params: { project: "hack0", var_name: "API_KEY" } },
      mockSecret,
      mockCtx,
    );
    expect(r.ok).toBe(false);
    expect(r.error?.code).toBe("auth_failed");
  });
});

describe("consumer-vercel-env.verify", () => {
  test("returns true when var exists and updatedAt is after createdAt", async () => {
    const now = Date.now();
    const secret = { ...mockSecret, createdAt: new Date(now - 5_000).toISOString() };
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            envs: [{ id: "env1", key: "API_KEY", updatedAt: new Date(now).toISOString() }],
          }),
          { status: 200 },
        ),
    );
    const r = await vercelEnvConsumer.verify?.(
      { type: "vercel-env", params: { project: "hack0", var_name: "API_KEY" } },
      secret,
      mockCtx,
    );
    expect(r?.ok).toBe(true);
    expect(r?.data).toBe(true);
  });
});
