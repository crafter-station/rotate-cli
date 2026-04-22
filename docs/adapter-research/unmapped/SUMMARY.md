---
provider: unmapped-summary
env_vars: []
management_api_base: n/a
auth_method: bearer
rotation_endpoint: n/a
ownership_strategy: none
confidence: medium
blockers: []
---

## Tiered classification

Tier 1: implement next.

| Provider | Why | Adapter shape | Estimated LOC |
| --- | --- | --- | --- |
| exa | Public Team Management API includes API key endpoints and team info. | Full adapter if create returns plaintext; otherwise manual create with automated list/revoke. | 300-450 |
| electric-sql | Official CLI exposes token lifecycle and service/resource listing through ORPC. | Split into `electric-token` for API tokens and manual-assist for `ELECTRIC_SECRET`. | 450-650 |
| vercel-blob | Official CLI uses Vercel storage store endpoints and token format leaks store id. | Ownership/list helper now; rotation only after Vercel exposes credential reset or user accepts manual replacement. | 350-550 |

Tier 2: useful manual-mode adapters.

| Provider | Why | Adapter shape | Estimated LOC |
| --- | --- | --- | --- |
| uploadthing | Dashboard-only rotation, but token/app id gives useful ownership hints. | Manual create/revoke, SDK liveness, format/sibling ownership. | 250-350 |
| trigger.dev | High impact by count, but no public key lifecycle endpoint found. | Manual create/revoke, safe liveness only if a non-mutating endpoint is confirmed. | 220-320 |
| firecrawl | No key lifecycle API, but common enough to guide rotation. | Manual create/revoke, avoid job-creating verification. | 180-280 |
| kapso | Internal platform likely can expose needed endpoints, but public docs/tools unavailable here. | Wait for internal API docs, then likely api-introspection. | 250-400 |

Tier 3: not worth a full adapter yet.

| Provider | Why | Adapter shape | Estimated LOC |
| --- | --- | --- | --- |
| groq | Inference API only; no key management or ownership endpoint. | Generic manual AI-key adapter can cover it. | 150-220 |
| mistral | Console-only key lifecycle; model endpoint gives liveness only. | Generic manual AI-key adapter can cover it. | 150-220 |
| luma | Generation API can be expensive; no management or ownership API. | Manual docs entry only unless account APIs appear. | 120-200 |

## Recommended implementation order

1. `adapter-exa`: best candidate for a full automated key lifecycle. First verification item is whether `POST /team-management/api-keys` returns plaintext once.
2. `adapter-uploadthing`: low-risk manual adapter with useful ownership from token/app id and high developer ergonomics.
3. `adapter-vercel-blob`: implement ownership and listing only; leave creation/revocation blocked unless user explicitly chooses new-store mode.
4. `adapter-electric-token`: target Electric API tokens, not `ELECTRIC_SECRET`; keep source/service secret rotation manual.
5. `adapter-trigger-dev`: manual-assist because impact is high, but avoid pretending rotation is automated.
6. `adapter-firecrawl`: manual-assist and liveness-only.
7. `adapter-kapso`: wait for internal docs or MCP access.
8. Defer `groq`, `mistral`, and `luma` unless a generic manual API key adapter is added.

## Cross-provider notes

- For dashboard-only providers, the adapter contract can still produce a `Secret` from a user-pasted value and automate downstream propagation, but `create()` and `revoke()` should report manual steps clearly.
- Avoid billable verification calls. Prefer `GET /models`, `GET /team`, `GET /keys`, or list endpoints.
- Do not infer `other` unless preload is complete for the relevant account/workspace.
- Keep `packages/` untouched for this research pass.

