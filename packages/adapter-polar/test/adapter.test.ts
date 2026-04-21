import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { AuthContext, Secret } from "@rotate/core/types";
import { polarAdapter } from "../src/index.ts";

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

const mockCtx: AuthContext = {
  kind: "env",
  varName: "POLAR_BOOTSTRAP_TOKEN",
  token: "polar_oat_bootstrap",
};

describe("adapter-polar.create", () => {
  test("calls Polar API and returns OAT Secret", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            organization_access_token: {
              id: "oat_new",
              created_at: "2026-04-20T05:00:00Z",
              modified_at: "2026-04-20T05:00:00Z",
              organization_id: "org_123",
              comment: "rotate-cli|prod",
              scopes: ["products:read", "organization_access_tokens:write"],
              expires_at: "2026-07-19T05:00:00Z",
              last_used_at: null,
            },
            token: "polar_oat_new",
          }),
          { status: 201 },
        ),
    );
    const result = await polarAdapter.create(
      {
        secretId: "polar-main",
        adapter: "polar",
        metadata: {
          organization_id: "org_123",
          scopes: "products:read,organization_access_tokens:write",
          comment: "rotate-cli|prod",
          expires_in: "P90D",
        },
      },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe("polar_oat_new");
    expect(result.data?.metadata.token_id).toBe("oat_new");
    expect(result.data?.expiresAt).toBe("2026-07-19T05:00:00Z");
    expect(calls[0]?.url).toContain("/v1/organization-access-tokens/");
    expect(calls[0]?.init?.method).toBe("POST");
  });

  test("calls Polar API and returns webhook Secret", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            id: "wh_123",
            url: "https://example.com/webhooks/polar",
            secret: "polar_whs_new",
            events: ["order.created"],
            format: "raw",
            organization_id: "org_123",
            enabled: true,
            modified_at: "2026-04-20T05:00:00Z",
          }),
          { status: 200 },
        ),
    );
    const result = await polarAdapter.create(
      {
        secretId: "polar-webhook",
        adapter: "polar",
        metadata: { kind: "webhook", webhook_endpoint_id: "wh_123" },
      },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe("polar_whs_new");
    expect(result.data?.metadata.webhook_endpoint_id).toBe("wh_123");
    expect(calls[0]?.url).toContain("/v1/webhooks/endpoints/wh_123/secret");
    expect(calls[0]?.init?.method).toBe("PATCH");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await polarAdapter.create(
      {
        secretId: "m",
        adapter: "polar",
        metadata: { scopes: "organization_access_tokens:write" },
      },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-polar.verify", () => {
  test("calls Polar API with new OAT", async () => {
    mockFetch(() => new Response(JSON.stringify({ items: [] }), { status: 200 }));
    const secret: Secret = {
      id: "oat_new",
      provider: "polar",
      value: "polar_oat_new",
      metadata: { kind: "oat" },
      createdAt: new Date().toISOString(),
    };
    const r = await polarAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toMatch(/\/v1\/organization-access-tokens\/\?page=1&limit=1$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer polar_oat_new",
    );
  });
});

describe("adapter-polar.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "oat_old",
      provider: "polar",
      value: "polar_oat_old",
      metadata: { kind: "oat", token_id: "oat_old" },
      createdAt: new Date().toISOString(),
    };
    const r = await polarAdapter.revoke(secret, mockCtx);
    expect(r.ok).toBe(true);
  });
});
