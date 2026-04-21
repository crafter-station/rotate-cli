# @rotate/adapter-local-random

Rotate app-owned secrets that have no external provider — `SESSION_SECRET`,
`JWT_SECRET`, `CRON_SECRET`, `HMAC_SECRET`, `AUTH_SECRET`, custom webhook
signing keys, etc.

Each rotation produces a fresh value generated locally via
`crypto.randomBytes`. Nothing is sent to the network. `revoke` is a no-op
because there is no provider to invalidate — the old value stops working
once every consumer has the new one and has redeployed.

## When to use

Use this adapter for any secret that your own code generates and validates.
Common shapes:

| Secret | Metadata |
|---|---|
| `SESSION_SECRET` | `{ bytes: 32, encoding: "base64url" }` |
| `JWT_SECRET` | `{ bytes: 64, encoding: "hex" }` |
| `CRON_SECRET` | `{ bytes: 32, encoding: "hex" }` |
| Stripe-shape webhook | `{ prefix: "whsec_", bytes: 32, encoding: "hex" }` |

Do **not** use this adapter for secrets issued by an external provider
(Stripe, Clerk, etc). Those need their provider-specific adapter so the
provider knows about the rotation.

## Auth

None. This adapter has no credentials — `auth()` returns a placeholder.

## Config example

```yaml
secrets:
  - id: session-secret
    adapter: local-random
    metadata:
      bytes: "32"
      encoding: base64url
    consumers:
      - type: vercel-env
        params:
          project: <vercel-project-id>
          team: <vercel-team-id>
          var_name: SESSION_SECRET

  - id: stripe-shape-webhook
    adapter: local-random
    metadata:
      bytes: "32"
      encoding: hex
      prefix: "whsec_"
    consumers:
      - type: local-env
        params:
          path: "./.env.local"
          var_name: CUSTOM_WEBHOOK_SECRET
```

## Metadata reference

| Key | Type | Default | Notes |
|---|---|---|---|
| `bytes` | number (as string) | `"32"` | Raw entropy before encoding. 32 bytes = 256 bits. Range: 16–128. |
| `encoding` | `hex` / `base64url` / `base64` | `"hex"` | `base64url` is URL-safe (no `+/=`). |
| `prefix` | string | `""` | Prepended verbatim. Useful for matching provider conventions (`whsec_`, `sk_`, etc). |

## Operations

- `create`: `crypto.randomBytes(n).toString(encoding)` with optional prefix.
- `verify`: decodes the value back and checks raw byte length matches
  `metadata.bytes`. Syntactic verification is the most we can do — there
  is no server to call.
- `revoke`: always returns `{ ok: true }`. The old value stays technically
  valid until consumers redeploy; the orchestrator's grace period is what
  protects against premature invalidation.
- `list`: not implemented. Locally-generated secrets aren't stored anywhere
  this adapter can enumerate.

## Why it exists

Half of real-world "Need to Rotate" env vars are self-generated app
secrets (nextauth sessions, custom cron guards, signed-URL HMAC keys).
They're the easiest to rotate — no provider dance — but the ones teams
rotate least often because there's no "rotate" button anywhere. This
adapter gives them one.
