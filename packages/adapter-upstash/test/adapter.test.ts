import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { getAuthDefinition } from "@rotate/core";
import { registerAdapter, resetRegistry } from "@rotate/core/registry";
import type { AuthContext, Secret } from "@rotate/core/types";
import { upstashAdapter } from "../src/index.ts";

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
  resetRegistry();
  registerAdapter(upstashAdapter);
  delete process.env.UPSTASH_EMAIL;
  delete process.env.UPSTASH_API_KEY;
});

afterEach(() => {
  global.fetch = originalFetch;
  resetRegistry();
  delete process.env.UPSTASH_EMAIL;
  delete process.env.UPSTASH_API_KEY;
});

const mockCtx: AuthContext = {
  kind: "env",
  varName: "UPSTASH_EMAIL,UPSTASH_API_KEY",
  token: "dev@example.com:mgmt_key",
};

describe("adapter-upstash.create", () => {
  test("calls reset-password and returns Secret", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            database_id: "db_123",
            rest_token: "rest_new",
            password: "password_new",
            last_password_rotation: "2026-04-21T12:00:00.000Z",
          }),
          { status: 200 },
        ),
    );
    const result = await upstashAdapter.create(
      { secretId: "main", adapter: "upstash", metadata: { database_id: "db_123" } },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.id).toBe("db_123");
    expect(result.data?.value).toBe("rest_new");
    expect(result.data?.metadata.database_id).toBe("db_123");
    expect(result.data?.createdAt).toBe("2026-04-21T12:00:00.000Z");
    expect(calls[0]?.url).toContain("/v2/redis/reset-password/db_123");
    expect(calls[0]?.init?.method).toBe("POST");
  });

  test("missing database_id returns invalid_spec", async () => {
    const result = await upstashAdapter.create(
      { secretId: "main", adapter: "upstash", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("invalid_spec");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await upstashAdapter.create(
      { secretId: "m", adapter: "upstash", metadata: { database_id: "db_123" } },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-upstash.verify", () => {
  test("calls database endpoint with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ database_id: "db_123" }), { status: 200 }));
    const secret: Secret = {
      id: "db_123",
      provider: "upstash",
      value: "rest_new",
      metadata: { database_id: "db_123" },
      createdAt: new Date().toISOString(),
    };
    const r = await upstashAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toMatch(/\/v2\/redis\/database\/db_123$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      `Basic ${Buffer.from("dev@example.com:rest_new").toString("base64")}`,
    );
  });
});

describe("adapter-upstash.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "db_123",
      provider: "upstash",
      value: "rest_old",
      metadata: { database_id: "db_123" },
      createdAt: new Date().toISOString(),
    };
    const r = await upstashAdapter.revoke(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls).toHaveLength(0);
  });
});

describe("adapter-upstash.auth", () => {
  test("resolves env auth through shared auth registry", async () => {
    process.env.UPSTASH_EMAIL = "dev@example.com";
    process.env.UPSTASH_API_KEY = "test-key";
    const ctx = await upstashAdapter.auth();
    expect(ctx.kind).toBe("env");
    expect(ctx.token).toBe("dev@example.com:test-key");
  });

  test("registers auth definition with the adapter", () => {
    expect(getAuthDefinition("upstash")?.displayName).toBe("Upstash");
  });
});

describe("adapter-upstash.ownedBy", () => {
  test("returns self when co-located REST URL matches the admin index", async () => {
    mockFetch((url) => {
      if (url.endsWith("/redis/databases")) {
        return json([
          {
            database_id: "db_123",
            endpoint: "relaxed-puma-43216.upstash.io",
            rest_token: "AXW_ASQgOTZh_self_token_value_1234567890=",
            read_only_rest_token: "AXW_ASQgOTZh_readonly_token_value_123456=",
            user_email: "dev@example.com",
          },
        ]);
      }
      if (url.endsWith("/teams")) return json([]);
      return new Response("not found", { status: 404 });
    });

    const result = await upstashAdapter.ownedBy?.(
      "AXW_ASQgOTZh_self_token_value_1234567890=",
      mockCtx,
      {
        coLocatedVars: {
          UPSTASH_REDIS_REST_URL: "https://relaxed-puma-43216.upstash.io",
        },
      },
    );

    expect(result?.verdict).toBe("self");
    expect(result?.adminCanBill).toBe(true);
    expect(result?.confidence).toBe("high");
    expect(result?.strategy).toBe("format-decode");
    expect(calls.map((call) => call.url)).toEqual([
      "https://api.upstash.com/v2/redis/databases",
      "https://api.upstash.com/v2/teams",
    ]);
  });

  test("returns other when REST URL endpoint is outside the admin index", async () => {
    mockFetch((url) => {
      if (url.endsWith("/redis/databases")) return json([]);
      if (url.endsWith("/teams")) return json([]);
      return new Response("not found", { status: 404 });
    });

    const result = await upstashAdapter.ownedBy?.("not-a-token", mockCtx, {
      coLocatedVars: {
        KV_REST_API_URL: "https://relaxed-puma-43216.upstash.io",
      },
    });

    expect(result?.verdict).toBe("other");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("high");
  });

  test("returns unknown on 401 while building the ownership index", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));

    const result = await upstashAdapter.ownedBy?.(
      "AXW_ASQgOTZh_unknown_token_value_1234567890=",
      mockCtx,
    );

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
  });

  test("returns unknown on network error while building the ownership index", async () => {
    mockFetch(() => {
      throw new Error("offline");
    });

    const result = await upstashAdapter.ownedBy?.(
      "AXW_ASQgOTZh_unknown_token_value_1234567890=",
      mockCtx,
    );

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
  });

  test("matches REST and read-only tokens from preload by hash", async () => {
    const preload = {
      dbByEndpoint: {
        "relaxed-puma-43216.upstash.io": {
          id: "db_123",
          endpoint: "relaxed-puma-43216.upstash.io",
          userEmail: "dev@example.com",
        },
      },
      tokenHashToEndpoint: {
        [sha256("AXW_ASQgOTZh_self_token_value_1234567890=")]: "relaxed-puma-43216.upstash.io",
        [sha256("AXW_ASQgOTZh_readonly_token_value_123456=")]: "relaxed-puma-43216.upstash.io",
      },
      selfEmails: ["dev@example.com"],
      selfTeamIds: [],
    };

    const result = await upstashAdapter.ownedBy?.(
      "AXW_ASQgOTZh_readonly_token_value_123456=",
      mockCtx,
      { preload },
    );

    expect(result?.verdict).toBe("self");
    expect(result?.strategy).toBe("list-match");
    expect(calls).toHaveLength(0);
  });

  test("uses Vercel KV redis URL aliases for endpoint ownership", async () => {
    const result = await upstashAdapter.ownedBy?.("rest token stored elsewhere", mockCtx, {
      coLocatedVars: {
        REDIS_URL: "rediss://default:password@relaxed-puma-43216.upstash.io:6379",
      },
      preload: {
        dbByEndpoint: {
          "relaxed-puma-43216.upstash.io": {
            id: "db_123",
            endpoint: "relaxed-puma-43216.upstash.io",
            teamId: "team_123",
          },
        },
        tokenHashToEndpoint: {},
        selfEmails: ["dev@example.com"],
        selfTeamIds: ["team_123"],
      },
    });

    expect(result?.verdict).toBe("self");
    expect(result?.scope).toBe("team");
    expect(result?.strategy).toBe("format-decode");
    expect(calls).toHaveLength(0);
  });
});

describe("adapter-upstash.preloadOwnership", () => {
  test("builds endpoint and token hash indexes", async () => {
    mockFetch((url) => {
      if (url.endsWith("/redis/databases")) {
        return json([
          {
            database_id: "db_123",
            endpoint: "relaxed-puma-43216.upstash.io",
            rest_token: "AXW_ASQgOTZh_self_token_value_1234567890=",
            read_only_rest_token: "AXW_ASQgOTZh_readonly_token_value_123456=",
            team_id: "team_123",
            user_email: "dev@example.com",
          },
        ]);
      }
      if (url.endsWith("/teams")) {
        return json([{ team_id: "team_123" }]);
      }
      return new Response("not found", { status: 404 });
    });

    const preload = await upstashAdapter.preloadOwnership?.(mockCtx);

    expect(preload?.dbByEndpoint).toEqual({
      "relaxed-puma-43216.upstash.io": {
        id: "db_123",
        endpoint: "relaxed-puma-43216.upstash.io",
        teamId: "team_123",
        userEmail: "dev@example.com",
      },
    });
    expect(preload?.tokenHashToEndpoint).toEqual({
      [sha256("AXW_ASQgOTZh_self_token_value_1234567890=")]: "relaxed-puma-43216.upstash.io",
      [sha256("AXW_ASQgOTZh_readonly_token_value_123456=")]: "relaxed-puma-43216.upstash.io",
    });
    expect(preload?.selfTeamIds).toEqual(["team_123"]);
    expect(preload?.selfEmails).toEqual(["dev@example.com"]);
  });
});

function json(value: unknown): Response {
  return new Response(JSON.stringify(value), { status: 200 });
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
