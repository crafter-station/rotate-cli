import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { AuthContext, Secret } from "@rotate/core/types";
import { githubActionsConsumer } from "../src/index.ts";

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

const mockCtx: AuthContext = { kind: "env", varName: "GITHUB_TOKEN", token: "ghp_test" };
const mockSecret: Secret = {
  id: "key",
  provider: "openai",
  value: "sk-live-new",
  metadata: {},
  createdAt: new Date().toISOString(),
};

describe("consumer-github-actions.propagate", () => {
  test("creates secret when delete is already absent", async () => {
    const publicKey = "rUC6RUqmQ2AsD/T4gi9wJwo0Pe3LD4A8dOmxcCojLmo=";
    mockFetch((url, init) => {
      if (url.includes("/actions/secrets/API_KEY") && init?.method === "DELETE") {
        return new Response("not found", { status: 404 });
      }
      if (url.includes("/actions/secrets/public-key")) {
        return new Response(JSON.stringify({ key_id: "key-id", key: publicKey }), { status: 200 });
      }
      if (url.includes("/actions/secrets/API_KEY") && init?.method === "PUT") {
        return new Response("", { status: 201 });
      }
      return new Response("unexpected", { status: 500 });
    });
    const r = await githubActionsConsumer.propagate(
      {
        type: "github-actions",
        params: { repo: "crafter-station/elements", secret_name: "API_KEY" },
      },
      mockSecret,
      mockCtx,
    );
    expect(r.ok).toBe(true);
    expect(calls[0]?.init?.method).toBe("DELETE");
    expect(calls.some((c) => c.url.includes("/actions/secrets/public-key"))).toBe(true);
    expect(calls.some((c) => c.init?.method === "PUT")).toBe(true);
  });

  test("deletes existing then recreates", async () => {
    let deleteCalled = false;
    const publicKey = "rUC6RUqmQ2AsD/T4gi9wJwo0Pe3LD4A8dOmxcCojLmo=";
    mockFetch((url, init) => {
      if (url.includes("/actions/secrets/API_KEY") && init?.method === "DELETE") {
        deleteCalled = true;
        return new Response("", { status: 204 });
      }
      if (url.includes("/actions/secrets/public-key")) {
        return new Response(JSON.stringify({ key_id: "key-id", key: publicKey }), { status: 200 });
      }
      if (url.includes("/actions/secrets/API_KEY") && init?.method === "PUT") {
        return new Response("", { status: 204 });
      }
      return new Response("unexpected", { status: 500 });
    });
    const r = await githubActionsConsumer.propagate(
      {
        type: "github-actions",
        params: { repo: "crafter-station/elements", secret_name: "API_KEY" },
      },
      mockSecret,
      mockCtx,
    );
    expect(r.ok).toBe(true);
    expect(deleteCalled).toBe(true);
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const r = await githubActionsConsumer.propagate(
      {
        type: "github-actions",
        params: { repo: "crafter-station/elements", secret_name: "API_KEY" },
      },
      mockSecret,
      mockCtx,
    );
    expect(r.ok).toBe(false);
    expect(r.error?.code).toBe("auth_failed");
  });
});

describe("consumer-github-actions.verify", () => {
  test("returns true when secret exists and updated_at is after createdAt", async () => {
    const now = Date.now();
    const secret = { ...mockSecret, createdAt: new Date(now - 5_000).toISOString() };
    mockFetch(
      () =>
        new Response(JSON.stringify({ updated_at: new Date(now).toISOString() }), {
          status: 200,
        }),
    );
    const r = await githubActionsConsumer.verify?.(
      {
        type: "github-actions",
        params: { repo: "crafter-station/elements", secret_name: "API_KEY" },
      },
      secret,
      mockCtx,
    );
    expect(r?.ok).toBe(true);
    expect(r?.data).toBe(true);
  });
});
