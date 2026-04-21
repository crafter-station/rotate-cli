import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { resolveCurrentValue } from "../src/current-value.ts";

type FetchFn = typeof fetch;
const originalFetch = global.fetch;
const originalEnv = { ...process.env };

function mockFetch(responder: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  global.fetch = ((url: RequestInfo | URL, init?: RequestInit) => {
    const u = typeof url === "string" ? url : url.toString();
    return Promise.resolve(responder(u, init));
  }) as FetchFn;
}

beforeEach(() => {
  process.env = { ...originalEnv };
  delete process.env.VERCEL_TOKEN;
});

afterEach(() => {
  global.fetch = originalFetch;
  process.env = { ...originalEnv };
});

describe("resolveCurrentValue", () => {
  test("env override wins over vercel pull", async () => {
    process.env.FOO_CURRENT = "from-env";
    const r = await resolveCurrentValue({
      id: "x",
      adapter: "mock",
      currentValueEnv: "FOO_CURRENT",
      consumers: [{ type: "vercel-env", params: { project: "p", var_name: "FOO" } }],
    });
    expect(r.value).toBe("from-env");
    expect(r.source).toBe("env");
  });

  test("literal override", async () => {
    const r = await resolveCurrentValue({
      id: "x",
      adapter: "mock",
      currentValue: "sk-literal",
      consumers: [],
    });
    expect(r.value).toBe("sk-literal");
    expect(r.source).toBe("literal");
  });

  test("pull from Vercel when consumer is vercel-env", async () => {
    process.env.VERCEL_TOKEN = "verc_test";
    mockFetch((url) => {
      if (url.includes("/v9/projects/") && url.includes("/env?")) {
        return new Response(
          JSON.stringify({
            envs: [{ id: "env_abc", key: "FOO", type: "encrypted" }],
          }),
          { status: 200 },
        );
      }
      if (url.includes("/v1/projects/") && url.includes("/env/env_abc")) {
        return new Response(JSON.stringify({ value: "sk-decrypted" }), { status: 200 });
      }
      return new Response("unexpected", { status: 500 });
    });

    const r = await resolveCurrentValue({
      id: "x",
      adapter: "mock",
      consumers: [{ type: "vercel-env", params: { project: "proj1", var_name: "FOO" } }],
    });
    expect(r.source).toBe("vercel-api");
    expect(r.value).toBe("sk-decrypted");
  });

  test("sensitive env returns null (cannot decrypt)", async () => {
    process.env.VERCEL_TOKEN = "verc_test";
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            envs: [{ id: "env_abc", key: "FOO", type: "sensitive" }],
          }),
          { status: 200 },
        ),
    );

    const r = await resolveCurrentValue({
      id: "x",
      adapter: "mock",
      consumers: [{ type: "vercel-env", params: { project: "p", var_name: "FOO" } }],
    });
    expect(r.value).toBeNull();
    expect(r.source).toBe("unavailable");
  });

  test("Vercel list 403 captured as error", async () => {
    process.env.VERCEL_TOKEN = "verc_test";
    mockFetch(() => new Response("forbidden", { status: 403 }));

    const r = await resolveCurrentValue({
      id: "x",
      adapter: "mock",
      consumers: [{ type: "vercel-env", params: { project: "p", var_name: "FOO" } }],
    });
    expect(r.value).toBeNull();
    expect(r.source).toBe("error");
    expect(r.error).toContain("403");
  });

  test("no vercel consumer + no env/literal → unavailable", async () => {
    const r = await resolveCurrentValue({
      id: "x",
      adapter: "mock",
      consumers: [{ type: "github-actions", params: { repo: "owner/repo", secret_name: "FOO" } }],
    });
    expect(r.value).toBeNull();
    expect(r.source).toBe("unavailable");
  });
});
