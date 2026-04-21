import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeStoredCredential } from "../src/auth-store.ts";
import {
  getAuthDefinition,
  listAuthEntries,
  registerAuthDefinition,
  resolveRegisteredAuth,
} from "../src/auth.ts";
import { registerAdapter, resetRegistry } from "../src/registry.ts";
import type { Adapter, AuthDefinition } from "../src/types.ts";

const originalStateDir = process.env.ROTATE_CLI_STATE_DIR;
const originalToken = process.env.OPENAI_ADMIN_KEY;

function makeDefinition(): AuthDefinition {
  return {
    name: "openai",
    displayName: "OpenAI",
    envVars: ["OPENAI_ADMIN_KEY"],
    async resolve() {
      const envToken = process.env.OPENAI_ADMIN_KEY;
      if (envToken) return { kind: "env" as const, varName: "OPENAI_ADMIN_KEY", token: envToken };
      const token = "stored-token";
      return { kind: "encrypted-file" as const, path: "ignored", token };
    },
    async login() {
      return { kind: "env" as const, varName: "OPENAI_ADMIN_KEY", token: "sk-admin" };
    },
  };
}

beforeEach(() => {
  process.env.ROTATE_CLI_STATE_DIR = mkdtempSync(join(tmpdir(), "rotate-auth-test-"));
  delete process.env.OPENAI_ADMIN_KEY;
  resetRegistry();
});

afterEach(() => {
  resetRegistry();
  if (originalStateDir) process.env.ROTATE_CLI_STATE_DIR = originalStateDir;
  else delete process.env.ROTATE_CLI_STATE_DIR;
  if (originalToken) process.env.OPENAI_ADMIN_KEY = originalToken;
  else delete process.env.OPENAI_ADMIN_KEY;
});

describe("auth registry", () => {
  test("resolveRegisteredAuth prefers env over stored auth", async () => {
    writeStoredCredential("openai", "stored-token");
    registerAuthDefinition({
      ...makeDefinition(),
      async resolve() {
        const envToken = process.env.OPENAI_ADMIN_KEY;
        if (envToken) {
          return { kind: "env" as const, varName: "OPENAI_ADMIN_KEY", token: envToken };
        }
        return { kind: "encrypted-file" as const, path: "stored", token: "stored-token" };
      },
    });
    process.env.OPENAI_ADMIN_KEY = "env-token";
    const ctx = await resolveRegisteredAuth("openai");
    expect(ctx.kind).toBe("env");
    expect(ctx.token).toBe("env-token");
  });

  test("listAuthEntries reports stored auth", async () => {
    writeStoredCredential("openai", "stored-token");
    registerAuthDefinition({
      ...makeDefinition(),
      async resolve() {
        return { kind: "encrypted-file" as const, path: "stored", token: "stored-token" };
      },
    });
    const entries = await listAuthEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0]?.status).toBe("configured");
    expect(entries[0]?.source).toBe("stored");
  });

  test("duplicate auth registration throws", () => {
    registerAuthDefinition(makeDefinition());
    expect(() => registerAuthDefinition(makeDefinition())).toThrow(
      /auth definition already registered: openai/,
    );
  });

  test("registerAdapter auto-registers auth definition", () => {
    const adapter: Adapter = {
      name: "openai",
      authDefinition: makeDefinition(),
      async auth() {
        return { kind: "env", varName: "OPENAI_ADMIN_KEY", token: "token" };
      },
      async create() {
        throw new Error("not implemented");
      },
      async verify() {
        throw new Error("not implemented");
      },
      async revoke() {
        throw new Error("not implemented");
      },
    };
    registerAdapter(adapter);
    expect(getAuthDefinition("openai")?.displayName).toBe("OpenAI");
  });

  test("registerAdapter rejects mismatched auth definition names", () => {
    const adapter: Adapter = {
      name: "openai",
      authRef: "openai",
      authDefinition: {
        ...makeDefinition(),
        name: "other",
      },
      async auth() {
        return { kind: "env", varName: "OPENAI_ADMIN_KEY", token: "token" };
      },
      async create() {
        throw new Error("not implemented");
      },
      async verify() {
        throw new Error("not implemented");
      },
      async revoke() {
        throw new Error("not implemented");
      },
    };
    expect(() => registerAdapter(adapter)).toThrow(/adapter auth definition mismatch/);
  });
});
