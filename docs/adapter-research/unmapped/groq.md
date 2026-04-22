---
provider: groq
env_vars: [GROQ_API_KEY]
management_api_base: https://api.groq.com
auth_method: bearer
rotation_endpoint: no public API
ownership_strategy: none
confidence: high
blockers: [No documented public API key create/list/delete endpoints, no documented organization or key introspection endpoint, OpenAI-compatible endpoints verify liveness only]
---

## Rotation flow

Groq exposes OpenAI-compatible inference APIs under `https://api.groq.com/openai/v1`. Public API docs cover chat, responses, audio, models, batches, files, and fine-tuning style endpoints, all authenticated with `Authorization: Bearer <GROQ_API_KEY>`.

No public management API for API keys was found.

Manual-assist adapter flow:

1. `verify()` calls `GET /openai/v1/models` with the candidate key.
2. `create()` opens or points to the Groq Console API Keys page and asks the user to paste a new key.
3. `revoke()` asks the user to delete the old key from the console.

## Ownership detection

No public ownership endpoint found. `GET /openai/v1/models` confirms that a key is accepted, but the response is model inventory rather than user/org identity.

`ownedBy(value, ctx)` should return `unknown`.

## preloadOwnership (if applicable)

Not applicable until Groq publishes org/key management endpoints.

## Gotchas

- Groq API keys are opaque; do not parse prefixes for ownership.
- Some product endpoints can create billable work; verification should use `GET /openai/v1/models`.
- Console settings and API key UI may be team-aware, but this is not currently exposed as a public API.

## References

- https://console.groq.com/docs/api-reference
- https://console.groq.com/docs/quickstart
- https://console.groq.com/keys
- npm: `groq-sdk`

