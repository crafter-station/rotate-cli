import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { AuthContext, Secret } from "@rotate/core/types";
import { neonConnectionAdapter } from "../src/index.ts";

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

const mockCtx: AuthContext = { kind: "env", varName: "NEON_API_KEY", token: "neon_test" };

describe("adapter-neon-connection.create", () => {
  test("calls Neon API and returns Secret", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            role: {
              password: "new_pwd",
            },
          }),
          { status: 200 },
        ),
    );
    const result = await neonConnectionAdapter.create(
      {
        secretId: "database-url",
        adapter: "neon-connection",
        metadata: {
          project_id: "prj_x",
          branch_id: "br_x",
          role_name: "app",
          database_name: "main",
          host: "ep-test.us-east-1.aws.neon.tech",
          pooled_host: "ep-test-pooler.us-east-1.aws.neon.tech",
          unpooled_host: "ep-test.us-east-1.aws.neon.tech",
        },
      },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.id).toBe("prj_x/br_x/app");
    expect(result.data?.value).toBe(
      "postgresql://app:new_pwd@ep-test.us-east-1.aws.neon.tech/main?sslmode=require",
    );
    expect(result.data?.metadata.project_id).toBe("prj_x");
    expect(result.data?.metadata.branch_id).toBe("br_x");
    expect(result.data?.metadata.pooled_connection_string).toBe(
      "postgresql://app:new_pwd@ep-test-pooler.us-east-1.aws.neon.tech/main?sslmode=require",
    );
    expect(calls[0]?.url).toContain("/projects/prj_x/branches/br_x/roles/app/reset_password");
  });

  test("defaults branch_id to main", async () => {
    mockFetch(
      () =>
        new Response(JSON.stringify({ role: { password: "new_pwd" } }), {
          status: 200,
        }),
    );
    const result = await neonConnectionAdapter.create(
      {
        secretId: "database-url",
        adapter: "neon-connection",
        metadata: {
          project_id: "prj_x",
          role_name: "app",
          database_name: "main",
          host: "ep-test.us-east-1.aws.neon.tech",
        },
      },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.metadata.branch_id).toBe("main");
    expect(calls[0]?.url).toContain("/projects/prj_x/branches/main/roles/app/reset_password");
  });

  test("missing project_id returns invalid_spec", async () => {
    const result = await neonConnectionAdapter.create(
      {
        secretId: "database-url",
        adapter: "neon-connection",
        metadata: {
          role_name: "app",
          database_name: "main",
          host: "ep-test.us-east-1.aws.neon.tech",
        },
      },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("invalid_spec");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await neonConnectionAdapter.create(
      {
        secretId: "database-url",
        adapter: "neon-connection",
        metadata: {
          project_id: "prj_x",
          branch_id: "br_x",
          role_name: "app",
          database_name: "main",
          host: "ep-test.us-east-1.aws.neon.tech",
        },
      },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-neon-connection.verify", () => {
  test("calls /projects/{project_id} with Neon API key", async () => {
    mockFetch(() => new Response(JSON.stringify({ project: { id: "prj_x" } }), { status: 200 }));
    const secret: Secret = {
      id: "prj_x/br_x/app",
      provider: "neon-connection",
      value: "postgresql://app:new_pwd@ep-test.us-east-1.aws.neon.tech/main?sslmode=require",
      metadata: { project_id: "prj_x" },
      createdAt: new Date().toISOString(),
    };
    const r = await neonConnectionAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toMatch(/\/projects\/prj_x$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer neon_test",
    );
  });
});

describe("adapter-neon-connection.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "prj_x/br_x/app",
      provider: "neon-connection",
      value: "postgresql://app:old_pwd@ep-test.us-east-1.aws.neon.tech/main?sslmode=require",
      metadata: { project_id: "prj_x", branch_id: "br_x", role_name: "app" },
      createdAt: new Date().toISOString(),
    };
    const r = await neonConnectionAdapter.revoke(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls).toHaveLength(0);
  });
});
