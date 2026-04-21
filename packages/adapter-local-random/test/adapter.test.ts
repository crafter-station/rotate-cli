import { describe, expect, test } from "bun:test";
import type { AuthContext, RotationSpec, Secret } from "@rotate/core/types";
import { localRandomAdapter } from "../src/index.ts";

const spec = (metadata: Record<string, string>): RotationSpec => ({
  secretId: "session",
  adapter: "local-random",
  metadata,
});

const ctx: AuthContext = { kind: "env", varName: "X", token: "local" };

describe("adapter-local-random.create", () => {
  test("default: 32 bytes hex → 64 chars", async () => {
    const r = await localRandomAdapter.create(spec({}), ctx);
    expect(r.ok).toBe(true);
    expect(r.data?.value).toMatch(/^[0-9a-f]{64}$/);
    expect(r.data?.metadata.bytes).toBe("32");
    expect(r.data?.metadata.encoding).toBe("hex");
  });

  test("custom bytes=64 hex → 128 chars", async () => {
    const r = await localRandomAdapter.create(spec({ bytes: "64" }), ctx);
    expect(r.ok).toBe(true);
    expect(r.data?.value).toHaveLength(128);
  });

  test("base64url encoding is URL-safe (no =/+/=)", async () => {
    const r = await localRandomAdapter.create(spec({ encoding: "base64url" }), ctx);
    expect(r.ok).toBe(true);
    expect(r.data?.value).not.toMatch(/[+/=]/);
  });

  test("prefix is preserved", async () => {
    const r = await localRandomAdapter.create(
      spec({ prefix: "whsec_", bytes: "32", encoding: "hex" }),
      ctx,
    );
    expect(r.ok).toBe(true);
    expect(r.data?.value).toMatch(/^whsec_[0-9a-f]{64}$/);
    expect(r.data?.metadata.prefix).toBe("whsec_");
  });

  test("two invocations produce different values (non-determinism)", async () => {
    const [a, b] = await Promise.all([
      localRandomAdapter.create(spec({}), ctx),
      localRandomAdapter.create(spec({}), ctx),
    ]);
    expect(a.data?.value).not.toBe(b.data?.value);
  });

  test("invalid bytes=out-of-range returns invalid_spec", async () => {
    const r = await localRandomAdapter.create(spec({ bytes: "8" }), ctx);
    expect(r.ok).toBe(false);
    expect(r.error?.code).toBe("invalid_spec");
  });

  test("invalid encoding returns invalid_spec", async () => {
    const r = await localRandomAdapter.create(spec({ encoding: "rot13" }), ctx);
    expect(r.ok).toBe(false);
    expect(r.error?.code).toBe("invalid_spec");
  });
});

describe("adapter-local-random.verify", () => {
  test("verifies a freshly-created secret", async () => {
    const created = await localRandomAdapter.create(
      spec({ bytes: "32", encoding: "hex", prefix: "whsec_" }),
      ctx,
    );
    const ok = await localRandomAdapter.verify(created.data!, ctx);
    expect(ok.ok).toBe(true);
    expect(ok.data).toBe(true);
  });

  test("rejects wrong length", async () => {
    const secret: Secret = {
      id: "s",
      provider: "local-random",
      value: "abcd",
      metadata: { bytes: "32", encoding: "hex" },
      createdAt: new Date().toISOString(),
    };
    const r = await localRandomAdapter.verify(secret, ctx);
    expect(r.data).toBe(false);
  });

  test("rejects missing prefix", async () => {
    const created = await localRandomAdapter.create(spec({ prefix: "whsec_" }), ctx);
    // Strip the prefix from value, verify should fail.
    const tampered: Secret = {
      ...created.data!,
      value: created.data!.value.slice("whsec_".length),
    };
    const r = await localRandomAdapter.verify(tampered, ctx);
    expect(r.data).toBe(false);
  });
});

describe("adapter-local-random.revoke", () => {
  test("is a no-op that always succeeds", async () => {
    const dummy: Secret = {
      id: "s",
      provider: "local-random",
      value: "whatever",
      metadata: { bytes: "32", encoding: "hex" },
      createdAt: new Date().toISOString(),
    };
    const r = await localRandomAdapter.revoke(dummy, ctx);
    expect(r.ok).toBe(true);
  });
});

describe("adapter-local-random.auth", () => {
  test("returns a placeholder env ctx", async () => {
    const r = await localRandomAdapter.auth();
    expect(r.kind).toBe("env");
    expect(r.token).toBe("local");
  });
});
