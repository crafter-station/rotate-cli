import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { AuthContext, RotationSpec, Secret } from "@rotate/core/types";
import { defineRestAdapter } from "../src/index.ts";

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

interface FakeCreateResponse {
  id: string;
  value: string;
  created_at: string;
}

const fakeAdapter = defineRestAdapter<FakeCreateResponse>({
  name: "internal",
  baseUrl: "https://internal.example.test",
  authEnvVar: "INTERNAL_TOKEN",
  createEndpoint: "/v1/keys",
  verifyEndpoint: "/v1/me",
  revokeEndpoint: (secret) => `/v1/keys/${secret.metadata.key_id ?? secret.id}`,
  responseMapper: (body: FakeCreateResponse, spec: RotationSpec): Secret => ({
    id: body.id,
    provider: "internal",
    value: body.value,
    metadata: { key_id: body.id, secret_id: spec.secretId },
    createdAt: body.created_at,
  }),
});

const mockCtx: AuthContext = { kind: "env", varName: "INTERNAL_TOKEN", token: "old_token" };

describe("helpers-rest.create", () => {
  test("calls REST API and returns Secret", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            id: "key_new",
            value: "new_token",
            created_at: "2026-04-21T00:00:00.000Z",
          }),
          { status: 201 },
        ),
    );
    const result = await fakeAdapter.create(
      { secretId: "main", adapter: "internal", metadata: { scope: "test" } },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.id).toBe("key_new");
    expect(result.data?.value).toBe("new_token");
    expect(result.data?.metadata.secret_id).toBe("main");
    expect(calls[0]?.url).toBe("https://internal.example.test/v1/keys");
    expect(calls[0]?.init?.method).toBe("POST");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await fakeAdapter.create(
      { secretId: "main", adapter: "internal", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("helpers-rest.verify", () => {
  test("calls verify endpoint with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ id: "user_1" }), { status: 200 }));
    const secret: Secret = {
      id: "key_new",
      provider: "internal",
      value: "new_token",
      metadata: { key_id: "key_new" },
      createdAt: "2026-04-21T00:00:00.000Z",
    };
    const result = await fakeAdapter.verify(secret, mockCtx);
    expect(result.ok).toBe(true);
    expect(result.data).toBe(true);
    expect(calls[0]?.url).toBe("https://internal.example.test/v1/me");
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer new_token",
    );
  });
});

describe("helpers-rest.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "key_old",
      provider: "internal",
      value: "old_secret",
      metadata: { key_id: "key_old" },
      createdAt: "2026-04-21T00:00:00.000Z",
    };
    const result = await fakeAdapter.revoke(secret, mockCtx);
    expect(result.ok).toBe(true);
    expect(calls[0]?.url).toBe("https://internal.example.test/v1/keys/key_old");
  });
});
