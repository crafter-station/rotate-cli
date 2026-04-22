import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { getAuthDefinition } from "@rotate/core/auth";
import { registerAdapter, resetRegistry } from "@rotate/core/registry";
import type {
  AuthContext,
  PromptChoice,
  PromptConfirmOptions,
  PromptIO,
  Secret,
} from "@rotate/core/types";
import { adapterVercelBlobAdapter } from "../src/index.ts";

type FetchFn = typeof fetch;

const originalFetch = global.fetch;
let calls: Array<{ url: string; init?: RequestInit }> = [];

function mockFetch(responder: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  global.fetch = ((url: Parameters<FetchFn>[0], init?: RequestInit) => {
    const u = typeof url === "string" ? url : url.toString();
    calls.push({ url: u, init });
    return Promise.resolve(responder(u, init));
  }) as FetchFn;
}

class ScriptedIO implements PromptIO {
  readonly isInteractive: boolean;
  readonly notes: string[] = [];

  constructor(
    private readonly options: {
      interactive?: boolean;
      secrets?: string[];
      confirms?: boolean[];
    } = {},
  ) {
    this.isInteractive = options.interactive ?? true;
  }

  note(message: string): void {
    this.notes.push(message);
  }

  async promptLine(_message: string): Promise<string> {
    return "";
  }

  async promptSecret(_message: string): Promise<string> {
    return this.options.secrets?.shift() ?? "";
  }

  async select(_message: string, choices: PromptChoice[]): Promise<string> {
    return choices[0]?.value ?? "";
  }

  async confirm(_message: string, _options?: PromptConfirmOptions): Promise<boolean> {
    return this.options.confirms?.shift() ?? false;
  }

  async close(): Promise<void> {}
}

beforeEach(() => {
  calls = [];
  resetRegistry();
  registerAdapter(adapterVercelBlobAdapter);
  delete process.env.VERCEL_TOKEN;
});

afterEach(() => {
  global.fetch = originalFetch;
  resetRegistry();
  delete process.env.VERCEL_TOKEN;
});

const mockCtx: AuthContext = { kind: "env", varName: "VERCEL_TOKEN", token: "vercel_admin" };

describe("adapter-vercel-blob.create", () => {
  test("prompts for a replacement Blob token and returns a Secret", async () => {
    const io = new ScriptedIO({ secrets: ["vercel_blob_rw_abcd1234_extra"] });

    const result = await adapterVercelBlobAdapter.create(
      {
        secretId: "blob",
        adapter: "vercel-blob",
        metadata: { team_id: "team_1" },
        io,
      },
      mockCtx,
    );

    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe("vercel_blob_rw_abcd1234_extra");
    expect(result.data?.metadata.store_id).toBe("store_abcd1234");
    expect(result.data?.metadata.manual_assist).toBe("true");
    expect(io.notes[0]).toContain("manual-assist");
    expect(calls).toHaveLength(0);
  });

  test("non-interactive IO returns unsupported", async () => {
    const result = await adapterVercelBlobAdapter.create(
      {
        secretId: "blob",
        adapter: "vercel-blob",
        metadata: {},
        io: new ScriptedIO({ interactive: false }),
      },
      mockCtx,
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("unsupported");
  });
});

describe("adapter-vercel-blob.verify", () => {
  test("checks the token-derived store through Vercel management auth", async () => {
    mockFetch(
      () =>
        new Response(JSON.stringify({ store: { id: "store_abcd1234", name: "prod" } }), {
          status: 200,
        }),
    );
    const secret: Secret = {
      id: "store_abcd1234",
      provider: "vercel-blob",
      value: "vercel_blob_rw_abcd1234_extra",
      metadata: { team_id: "team_1" },
      createdAt: new Date().toISOString(),
    };

    const result = await adapterVercelBlobAdapter.verify(secret, mockCtx);

    expect(result.ok).toBe(true);
    expect(calls[0]?.url).toBe(
      "https://api.vercel.com/v1/storage/stores/store_abcd1234?teamId=team_1",
    );
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer vercel_admin",
    );
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const secret: Secret = {
      id: "store_abcd1234",
      provider: "vercel-blob",
      value: "vercel_blob_rw_abcd1234_extra",
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterVercelBlobAdapter.verify(secret, mockCtx);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-vercel-blob.revoke", () => {
  test("prints manual cleanup instructions and succeeds after confirmation", async () => {
    const io = new ScriptedIO({ confirms: [true] });
    const secret: Secret = {
      id: "store_abcd1234",
      provider: "vercel-blob",
      value: "vercel_blob_rw_abcd1234_extra",
      metadata: { store_id: "store_abcd1234" },
      createdAt: new Date().toISOString(),
    };

    const result = await adapterVercelBlobAdapter.revoke(secret, mockCtx, { io });

    expect(result.ok).toBe(true);
    expect(io.notes[0]).toContain("old credential cleanup");
    expect(calls).toHaveLength(0);
  });

  test("non-interactive IO returns unsupported", async () => {
    const secret: Secret = {
      id: "store_abcd1234",
      provider: "vercel-blob",
      value: "vercel_blob_rw_abcd1234_extra",
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterVercelBlobAdapter.revoke(secret, mockCtx, {
      io: new ScriptedIO({ interactive: false }),
    });

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("unsupported");
  });
});

describe("adapter-vercel-blob.ownedBy", () => {
  test("returns self when the token-derived store is readable", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            store: {
              id: "store_abcd1234",
              name: "prod",
              projectsMetadata: [{ projectId: "prj_1", name: "web" }],
            },
          }),
          { status: 200 },
        ),
    );

    const result = await adapterVercelBlobAdapter.ownedBy?.(
      "vercel_blob_rw_abcd1234_extra",
      mockCtx,
      { coLocatedVars: { team_id: "team_1" } },
    );

    expect(result?.verdict).toBe("self");
    expect(result?.scope).toBe("project");
    expect(result?.confidence).toBe("medium");
    expect(result?.strategy).toBe("format-decode");
  });

  test("returns other on 404 only when preload is complete", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));

    const result = await adapterVercelBlobAdapter.ownedBy?.(
      "vercel_blob_rw_missing_extra",
      mockCtx,
      {
        preload: {
          complete: true,
          stores: [{ id: "store_abcd1234", name: "prod" }],
        },
      },
    );

    expect(result?.verdict).toBe("other");
    expect(result?.adminCanBill).toBe(false);
  });

  test("uses sibling BLOB_STORE_ID when token parsing fails", async () => {
    mockFetch(
      () =>
        new Response(JSON.stringify({ store: { id: "store_sibling", name: "prod" } }), {
          status: 200,
        }),
    );

    const result = await adapterVercelBlobAdapter.ownedBy?.("not-a-token", mockCtx, {
      coLocatedVars: { BLOB_STORE_ID: "store_sibling" },
    });

    expect(result?.verdict).toBe("self");
    expect(calls[0]?.url).toBe("https://api.vercel.com/v1/storage/stores/store_sibling");
  });
});

describe("adapter-vercel-blob.auth", () => {
  test("resolves env auth through shared auth registry", async () => {
    process.env.VERCEL_TOKEN = "vercel_env";

    const ctx = await adapterVercelBlobAdapter.auth();

    expect(ctx.kind).toBe("env");
    expect(ctx.token).toBe("vercel_env");
  });

  test("registers auth definition with Blob env vars", () => {
    const definition = getAuthDefinition("vercel-blob");

    expect(definition?.displayName).toBe("Vercel Blob");
    expect(definition?.envVars).toContain("BLOB_READ_WRITE_TOKEN");
    expect(definition?.envVars).toContain("VERCEL_TOKEN");
  });
});
