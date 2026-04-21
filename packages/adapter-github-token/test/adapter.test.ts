import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { AuthContext, Secret } from "@rotate/core/types";
import { githubTokenAdapter } from "../src/index.ts";

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

const mockCtx: AuthContext = { kind: "env", varName: "GITHUB_TOKEN", token: "jwt_test" };

describe("adapter-github-token.create", () => {
  test("calls GitHub API and returns Secret", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            token: "ghs_1234567890abcdef",
            expires_at: "2026-04-21T19:00:00Z",
            repository_selection: "selected",
          }),
          { status: 201 },
        ),
    );
    const result = await githubTokenAdapter.create(
      {
        secretId: "main",
        adapter: "github",
        metadata: { installation_id: "123", repositories: "owner/repo" },
      },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe("ghs_1234567890abcdef");
    expect(result.data?.metadata.installation_id).toBe("123");
    expect(result.data?.expiresAt).toBe("2026-04-21T19:00:00Z");
    expect(calls[0]?.url).toContain("/app/installations/123/access_tokens");
  });

  test("missing installation_id returns invalid_spec", async () => {
    const result = await githubTokenAdapter.create(
      { secretId: "main", adapter: "github", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("invalid_spec");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await githubTokenAdapter.create(
      { secretId: "m", adapter: "github", metadata: { installation_id: "123" } },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-github-token.verify", () => {
  test("calls /installation/repositories with new secret", async () => {
    mockFetch(
      () => new Response(JSON.stringify({ total_count: 0, repositories: [] }), { status: 200 }),
    );
    const secret: Secret = {
      id: "github/installation/123/90abcdef",
      provider: "github",
      value: "ghs_1234567890abcdef",
      metadata: { installation_id: "123" },
      createdAt: new Date().toISOString(),
    };
    const r = await githubTokenAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toMatch(/\/installation\/repositories\?per_page=1$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer ghs_1234567890abcdef",
    );
  });
});

describe("adapter-github-token.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "github/installation/123/90abcdef",
      provider: "github",
      value: "ghs_1234567890abcdef",
      metadata: { installation_id: "123" },
      createdAt: new Date().toISOString(),
    };
    const r = await githubTokenAdapter.revoke(secret, mockCtx);
    expect(r.ok).toBe(true);
  });
});
