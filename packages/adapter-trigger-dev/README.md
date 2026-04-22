# @rotate/adapter-trigger-dev

Trigger.dev adapter for rotating project secret keys with manual dashboard assistance.

## Auth

- Primary runtime credential: `TRIGGER_SECRET_KEY`
- Related but separate credential class: `TRIGGER_ACCESS_TOKEN`
- Default API base: `https://api.trigger.dev`
- Override API base with `TRIGGER_API_URL` or `TRIGGER_DEV_API_URL`

The adapter verifies credentials with `GET /api/v1/query/schema` using bearer auth. This is a read-only Query API endpoint and does not enqueue runs.

## Rotation Strategy

Trigger.dev does not document a public management endpoint for creating, rotating, or revoking project secret keys. This adapter declares `mode: "manual-assist"`:

1. The user opens the Trigger.dev dashboard.
2. The user creates or reveals a replacement project environment secret key.
3. The adapter accepts the pasted key as the new `Secret`.
4. After propagation and verification, the user revokes the old key in the dashboard and confirms completion.

## Limitations

- `create()` and `revoke()` require interactive `PromptIO`.
- Non-interactive agent mode and CI return `unsupported`.
- Ownership detection returns `unknown` because Trigger.dev project secret key ownership is not publicly introspectable.
- Project refs, slugs, environments, and preview branches are preserved as metadata hints, but they do not prove ownership.
