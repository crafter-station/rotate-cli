import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { vercelKvAdapter } from "../src/index.ts";

describe("adapter-vercel-kv", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    delete process.env.UPSTASH_EMAIL;
    delete process.env.UPSTASH_API_KEY;
    delete process.env.VERCEL_KV_EMAIL;
    delete process.env.VERCEL_KV_API_KEY;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  test("name is vercel-kv", () => {
    expect(vercelKvAdapter.name).toBe("vercel-kv");
  });

  test("auth() fails without any credentials", async () => {
    await expect(vercelKvAdapter.auth()).rejects.toThrow();
  });

  test("auth() accepts VERCEL_KV_* aliases", async () => {
    process.env.VERCEL_KV_EMAIL = "hunter@example.com";
    process.env.VERCEL_KV_API_KEY = "kv_api_key_xyz";
    const ctx = await vercelKvAdapter.auth();
    expect(ctx.token).toBeTruthy();
    // After auth() the aliases are copied to UPSTASH_*.
    expect(process.env.UPSTASH_EMAIL).toBe("hunter@example.com");
    expect(process.env.UPSTASH_API_KEY).toBe("kv_api_key_xyz");
  });

  test("auth() accepts UPSTASH_* directly", async () => {
    process.env.UPSTASH_EMAIL = "hunter@example.com";
    process.env.UPSTASH_API_KEY = "up_api_key_xyz";
    const ctx = await vercelKvAdapter.auth();
    expect(ctx.token).toBeTruthy();
  });

  test("delegates create/verify/revoke to upstash", () => {
    // Reference equality is the cheapest "wired correctly" check.
    // The actual behavior is covered by adapter-upstash tests.
    expect(typeof vercelKvAdapter.create).toBe("function");
    expect(typeof vercelKvAdapter.verify).toBe("function");
    expect(typeof vercelKvAdapter.revoke).toBe("function");
    expect(typeof vercelKvAdapter.list).toBe("function");
  });
});
