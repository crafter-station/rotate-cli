import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { getAuthDefinition } from "@rotate/core/auth";
import { registerAdapter } from "@rotate/core/registry";
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
  delete process.env.NEON_API_KEY;
});

afterEach(() => {
  global.fetch = originalFetch;
  delete process.env.NEON_API_KEY;
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

describe("adapter-neon-connection.ownedBy", () => {
  test("returns self from decoded endpoint and warm index without calling Neon", async () => {
    mockFetch(() => new Response("should not be called", { status: 500 }));
    const result = await neonConnectionAdapter.ownedBy?.(
      "postgresql://app:secret@ep-cool-darkness-a1b2c3d4.us-east-2.aws.neon.tech/main?sslmode=require",
      mockCtx,
      {
        preload: {
          knownOrgIds: ["org_owned"],
          endpointToProject: {
            "ep-cool-darkness-a1b2c3d4": {
              projectId: "prj_owned",
              orgId: "org_owned",
            },
          },
        },
      },
    );

    expect(result?.verdict).toBe("self");
    expect(result?.adminCanBill).toBe(true);
    expect(result?.confidence).toBe("high");
    expect(result?.strategy).toBe("format-decode");
    expect(result?.scope).toBe("project");
    expect(result?.evidence).toContain("ep-cool-darkness-a1b2c3d4");
    expect(result?.evidence).not.toContain("secret");
    expect(calls).toHaveLength(0);
  });

  test("returns other when decoded endpoint maps outside known orgs", async () => {
    const result = await neonConnectionAdapter.ownedBy?.(
      "postgres://app:secret@ep-bright-river-abcdef-pooler.eu-central-1.aws.neon.tech/main",
      mockCtx,
      {
        preload: {
          knownOrgIds: ["org_owned"],
          endpointToProject: new Map([
            [
              "ep-bright-river-abcdef",
              {
                projectId: "prj_foreign",
                orgId: "org_foreign",
              },
            ],
          ]),
        },
      },
    );

    expect(result?.verdict).toBe("other");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("high");
    expect(result?.scope).toBe("project");
  });

  test("returns unknown when ownership index is unavailable", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await neonConnectionAdapter.ownedBy?.(
      "postgresql://app:secret@ep-cold-meadow-123abc.us-east-1.aws.neon.tech/main",
      mockCtx,
    );

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
    expect(result?.evidence).toBe(
      "endpoint ep-cold-meadow-123abc decoded, ownership index unavailable",
    );
    expect(calls).toHaveLength(0);
  });

  test("returns unknown when fetch would fail because ownedBy is zero-call", async () => {
    global.fetch = (() => Promise.reject(new Error("network down"))) as FetchFn;
    const result = await neonConnectionAdapter.ownedBy?.(
      "postgresql://app:secret@ep-missing-field-456def.us-east-1.aws.neon.tech/main",
      mockCtx,
    );

    expect(result?.verdict).toBe("unknown");
    expect(result?.evidence).toBe(
      "endpoint ep-missing-field-456def decoded, ownership index unavailable",
    );
  });

  test("returns self for legacy project query parameter shape", async () => {
    const result = await neonConnectionAdapter.ownedBy?.(
      "postgresql://app:secret@db.internal/main?options=project%3Dep-hidden-stream-789abc",
      mockCtx,
      {
        preload: {
          knownOrgIds: { personal: true },
          endpointToProject: {
            "ep-hidden-stream-789abc": {
              projectId: "prj_personal",
              orgId: null,
            },
          },
        },
      },
    );

    expect(result?.verdict).toBe("self");
    expect(result?.adminCanBill).toBe(true);
    expect(result?.evidence).toContain("owned org personal");
  });

  test("implements preloadOwnership to build ownership index from Neon API", () => {
    expect(typeof neonConnectionAdapter.preloadOwnership).toBe("function");
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

describe("adapter-neon-connection.auth", () => {
  test("resolves env auth through shared auth registry", async () => {
    registerNeonConnectionAuth();
    process.env.NEON_API_KEY = "test-token";
    const ctx = await neonConnectionAdapter.auth();
    expect(ctx.kind).toBe("env");
    expect(ctx.token).toBe("test-token");
  });

  test("registers auth definition with the adapter", () => {
    registerNeonConnectionAuth();
    expect(getAuthDefinition("neon-connection")?.displayName).toBe("Neon (connection strings)");
  });
});

function registerNeonConnectionAuth() {
  if (getAuthDefinition("neon-connection")) return;
  registerAdapter(neonConnectionAdapter);
}
