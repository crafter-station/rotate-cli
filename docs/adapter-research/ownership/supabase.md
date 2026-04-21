---
provider: supabase
verdict: format-decode (legacy JWT) + api-introspection (new sb_* keys)
cost: 0-calls (JWT) | 1-call (sb_secret_*)
certainty: high (JWT) | medium (sb_* opaque)
---

# Supabase — ownership detection

Target env vars: `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_ANON_KEY`, `SUPABASE_JWT_SECRET`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, and the new `sb_publishable_*` / `sb_secret_*`.

## Strategy

Two formats coexist in the wild (legacy deprecated after Oct 2025, but still in most production envs):

1. **Legacy JWT keys** (`eyJ...`) — anon + service_role. Payload includes `ref` claim = project ref. Pure format-decode, 0 network calls, cryptographic certainty.
2. **New opaque keys** (`sb_publishable_...`, `sb_secret_...`) — no project ref embedded (checksum only, not project-routing). Must introspect via Management API.
3. **`SUPABASE_JWT_SECRET`** — raw HS256 signing secret, base64 noise. No decodable content. Match by hashing against known projects' secrets if you have them, else unknown.
4. **`SUPABASE_URL`** (companion var, almost always co-located) — contains `https://{projectRef}.supabase.co`. Regex extract, always authoritative.

Order of precedence in `ownedBy()`:
1. Co-located `SUPABASE_URL` → regex for project ref → compare against admin's project list. **cost 0, certainty high**.
2. Decode key as JWT → read `ref` claim. **cost 0, certainty high**.
3. If opaque `sb_*` → call `GET /v1/projects` with admin PAT, iterate, fetch keys per project, match. **cost N, certainty high**.
4. Else → "unknown".

## Endpoints used

- **Format decode only** — no endpoint, parse JWT locally.
- **Management API** — `https://api.supabase.com`
  - `GET /v1/projects` → list all projects admin can see. Response includes `id` (project ref), `organization_id`, `name`, `region`.
  - `GET /v1/projects/{ref}/api-keys` → returns project's current `anon` and `service_role` (legacy) + `publishable_key` / `secret_key` (new). Use to compare against unknown secret.
  - Auth: `Authorization: Bearer {SUPABASE_PAT}` (personal access token, `sbp_...` prefix).

## Implementation hints (pseudocode)

```ts
type AdminCtx = {
  patToken: string;             // sbp_... admin PAT
  knownProjectRefs: Set<string>; // cached from GET /v1/projects
  keyIndex?: Map<string, string>; // sha256(secret) -> projectRef (built lazily)
};

function ownedBy(secret: string, coLocatedVars: Record<string,string>, ctx: AdminCtx): "self" | "other" | "unknown" {
  // Tier 1: cheap co-located URL
  const url = coLocatedVars.SUPABASE_URL ?? coLocatedVars.NEXT_PUBLIC_SUPABASE_URL;
  if (url) {
    const m = url.match(/^https?:\/\/([a-z]{20})\.supabase\.co/);
    if (m) return ctx.knownProjectRefs.has(m[1]) ? "self" : "other";
  }

  // Tier 2: legacy JWT — decode header.payload without verifying signature
  if (secret.startsWith("eyJ")) {
    const payload = decodeJwtPayload(secret); // base64url decode middle segment
    // expect: { iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon"|"service_role" }
    if (payload?.iss === "supabase" && typeof payload.ref === "string") {
      return ctx.knownProjectRefs.has(payload.ref) ? "self" : "other";
    }
  }

  // Tier 3: new opaque key — build sha256 index over admin's projects
  if (secret.startsWith("sb_publishable_") || secret.startsWith("sb_secret_")) {
    const idx = ctx.keyIndex ?? buildKeyIndex(ctx.patToken);
    const hit = idx.get(sha256(secret));
    if (hit) return "self";
    return "unknown"; // could be "other" — admin just can't see it
  }

  // Tier 4: JWT_SECRET (HS256 raw) — can't decode. Compare by bytewise equality to cached.
  if (/^[A-Za-z0-9+/=]{40,}$/.test(secret) && !secret.startsWith("eyJ")) {
    const jwtSecretIndex = ctx.jwtSecretIndex ?? buildJwtSecretIndex(ctx.patToken);
    return jwtSecretIndex.has(secret) ? "self" : "unknown";
  }

  return "unknown";
}

function buildKeyIndex(pat: string): Map<string, string> {
  const projects = fetch("https://api.supabase.com/v1/projects", { headers: { Authorization: `Bearer ${pat}` } });
  const map = new Map<string, string>();
  for (const p of projects) {
    const keys = fetch(`https://api.supabase.com/v1/projects/${p.id}/api-keys`, ...);
    for (const k of keys) map.set(sha256(k.api_key ?? k.secret), p.id);
  }
  return map;
}
```

## Edge cases

- **Self-hosted Supabase**: `iss` claim is often the self-host URL, not `"supabase"`. `ref` still present if Studio generated keys. Treat missing/different `iss` as "unknown" and fall back to URL match.
- **Project paused/deleted**: JWT still decodes to a valid `ref`; admin list won't contain it. Return "other" (correct — not yours anymore).
- **Rotated signing key**: JWT `ref` is baked in; signature is what changes. Decode still works without verifying.
- **`NEXT_PUBLIC_` prefix**: same value, strip prefix for matching.
- **`SUPABASE_JWT_SECRET` alone without key**: opaque base64, no embedded metadata. Only way is hashing against admin's `GET /v1/projects/{ref}/config/auth` (which exposes `jwt_secret` — sensitive).
- **New `sb_secret_*` with checksum**: the `_checksum` suffix does **not** encode project. It's just integrity (like Stripe key checksums). Project lookup requires network.
- **Project ref length**: always 20 lowercase alphanumeric chars (pattern `[a-z]{20}` — really `[a-z0-9]{20}` if newer refs). Use `[a-z0-9]{20}` for safety.

## Verdict summary

| Secret shape | Method | Cost | Certainty |
|---|---|---|---|
| Co-located `SUPABASE_URL` | Regex extract `ref` | 0 calls | High |
| Legacy JWT (`eyJ...`) | Decode `ref` claim | 0 calls | High |
| New `sb_publishable_*` | Hash-index vs admin keys | N + 1 calls | Medium (opaque) |
| New `sb_secret_*` | Hash-index vs admin keys | N + 1 calls | Medium |
| Raw `SUPABASE_JWT_SECRET` | Hash-compare vs admin configs | N calls | Medium |

## Sources

- [JWT Claims Reference | Supabase Docs](https://supabase.com/docs/guides/auth/jwt-fields) — confirms `iss`, `ref`, `role` on anon/service_role.
- [Understanding API keys | Supabase Docs](https://supabase.com/docs/guides/api/api-keys) — new `sb_publishable_*` / `sb_secret_*` format.
- [Supabase Management API — List projects](https://supabase.com/docs/reference/api/v1-list-all-projects) — `GET /v1/projects`.
- [JWT Signing Keys | Supabase Docs](https://supabase.com/docs/guides/auth/signing-keys) — legacy-to-asymmetric migration context.
