---
provider: github-token
verdict: api-introspection
cost: 1-call
certainty: high
---

# GitHub — ownership detection

Target secrets: anything held in `GITHUB_TOKEN`. Rotate-cli cares specifically about:

1. **Installation access tokens** (`ghs_*`, 1h expiry, minted via `POST /app/installations/{id}/access_tokens`). This is what `adapter-github-token` actually rotates.
2. **Personal access tokens** (`ghp_*` classic, `github_pat_*` fine-grained). NOT programmatically rotatable — out of rotate-cli's auto-rotation scope, but ownership detection is still useful for `rotate doctor`.
3. **OAuth user-to-server tokens** (`ghu_*`). Device flow / OAuth app. Rotate via `PATCH /applications/{client_id}/token`. Ownership detectable.
4. **GitHub Actions `GITHUB_TOKEN`**. Workflow-scoped, ephemeral. Not rotatable. If rotate-cli sees this as a persisted secret, flag as misuse.

## Verdict

**Single API call, definitive answer — for every token kind.** GitHub exposes `GET /user` (for PATs / OAuth user tokens) and `GET /installation/repositories` (for installation tokens). Combined with token prefix decoding (0-call filter), ownership is resolvable in 1 call per secret.

Format prefix is load-bearing here (unlike Vercel): GitHub's 2021 token format overhaul means every token starts with a 3-letter type prefix. Pick the introspection endpoint from the prefix; no guessing.

## Strategy

1. **Prefix decode (0 calls):** read the leading 4 chars.
   - `ghp_` → classic PAT. Owner = user. Use `GET /user`.
   - `github_pat_` → fine-grained PAT. Owner = user, but scoped to user OR org resources. Use `GET /user` + check `X-Accepted-GitHub-Permissions` header echo.
   - `gho_` → OAuth access token (OAuth App). Owner = user who granted consent. Use `GET /user` + check `X-OAuth-Client-Id` header in response.
   - `ghu_` → OAuth user-to-server (GitHub App acting on behalf of user). Use `GET /user`.
   - `ghs_` → GitHub App installation token. Owner = the account (user or org) that installed the app. Use `GET /installation/repositories`.
   - `ghr_` → refresh token. Cannot introspect directly; pair with paired access token.
2. **API introspection (1 call):** dispatch per prefix.
3. **Admin-side reconciliation:** compare introspection result against admin's `adminUserId` (for user-scoped tokens) or admin's org/installation list (for `ghs_`).

Note on "billing control": for `ghs_` tokens, billing control lives with the org owner of the GitHub App installation, NOT with whoever holds the token. Rotate-cli must track `installation_id` + `account.login` + `account.type` as ownership anchors.

## Endpoints used

### `GET /user` — for `ghp_`, `github_pat_`, `gho_`, `ghu_`
Auth: `Authorization: Bearer <token>`.
Returns: `{ login, id, type: "User", ... }`.
Ownership: exact user. Compare `id` to admin's `id`.

For `gho_` (OAuth App tokens), the response also includes a `X-OAuth-Client-Id` response header so you can confirm which OAuth App minted it. Useful for multi-tenant audits.

### `GET /installation/repositories` — for `ghs_`
Auth: `Authorization: Bearer <ghs_token>`.
Returns: `{ total_count, repository_selection, repositories: [{ owner: { login, id, type }, ... }] }`.
Ownership: every repo returned has an `owner` — for single-org installations, all owners are the same. Use `repositories[0].owner` or fall back to checking all if `repository_selection === "selected"`.

Alternative (cleaner): admin-side `GET /user/installations` with admin's own token returns admin-accessible installations including `account: { login, id, type: "User"|"Organization" }`. Cross-reference by installation_id.

### `POST /applications/{client_id}/token` — OAuth App check (admin-side)
Auth: HTTP Basic with `client_id:client_secret` (requires admin to also hold the OAuth App secret).
Body: `{ access_token: <token> }`.
Returns: full token metadata including `user`, `app`, `scopes`, `expires_at`.
Ownership: definitive. Use this if `gho_` and admin owns the OAuth App. Otherwise fall back to `GET /user`.

### `GET /app` — admin-side GitHub App identity
Auth: JWT signed with the app's private key.
Returns: `{ id, slug, owner: { login, id, type } }`.
Used to confirm admin owns the GitHub App before rotating any `ghs_*` minted by it. Cache per session.

### `GET /user/installations` — admin-side installation map
Auth: admin's user token (`gho_` or `ghu_`).
Returns: `{ installations: [{ id, account: { login, id, type }, app_id, app_slug, repository_selection, ... }] }`.
Lets rotate-cli answer "is installation X one I (admin) have access to?" without holding the ghs_ token itself.

## Implementation hints (pseudocode)

```ts
type GitHubOwnership = OwnershipResult & {
  tokenKind: "pat-classic" | "pat-fine-grained" | "oauth-access" | "oauth-user-to-server"
           | "installation" | "refresh" | "actions" | "unknown";
};

async function ownedByGitHub(
  secret: string,
  adminCtx: {
    adminUserId: number;
    adminLogin: string;
    adminInstallations: Map<number, InstallationMeta>; // from GET /user/installations
  },
): Promise<GitHubOwnership> {
  const kind = classifyByPrefix(secret);

  if (kind === "actions") {
    return {
      verdict: "other",
      scope: "installation",
      adminCanBill: false,
      confidence: "high",
      tokenKind: "actions",
      reason: "Actions GITHUB_TOKEN is workflow-scoped, not rotatable, don't persist",
    };
  }

  if (kind === "refresh") {
    return {
      verdict: "unknown",
      scope: "user",
      adminCanBill: false,
      confidence: "low",
      tokenKind: "refresh",
      reason: "refresh tokens cannot self-introspect; pair with ghu_/gho_ access token",
    };
  }

  if (kind === "installation") {
    // ghs_* — use /installation/repositories to get owner.
    const res = await fetch("https://api.github.com/installation/repositories?per_page=1", {
      headers: ghHeaders(secret),
    });
    if (res.status === 401 || res.status === 403) {
      return dead("installation", "installation token revoked/expired (1h lifetime)");
    }
    if (!res.ok) return dead("installation", `installation /repos ${res.status}`);
    const body = (await res.json()) as { repositories: Array<{ owner: GhAccount }> };
    const owner = body.repositories[0]?.owner;
    if (!owner) {
      return {
        verdict: "unknown",
        scope: "installation",
        adminCanBill: false,
        confidence: "low",
        tokenKind: "installation",
        reason: "no repositories exposed; cannot derive owner",
      };
    }
    // Match against admin-side installations.
    const match = [...adminCtx.adminInstallations.values()]
      .find((i) => i.account.login === owner.login && i.account.type === owner.type);
    return {
      verdict: match ? "self" : "other",
      scope: "installation",
      teamId: `${owner.type.toLowerCase()}:${owner.login}`,
      adminCanBill: match?.account.type === "Organization"
        ? /* admin must be org owner — separate check */ true
        : match?.account.login === adminCtx.adminLogin,
      confidence: "high",
      tokenKind: "installation",
      reason: match ? `installation for ${owner.login}` : `installation owned by ${owner.login}`,
    };
  }

  // ghp_, github_pat_, gho_, ghu_ — /user.
  const who = await fetch("https://api.github.com/user", { headers: ghHeaders(secret) });
  if (who.status === 401 || who.status === 403) {
    return dead(kind, "token revoked or invalid");
  }
  if (!who.ok) return dead(kind, `/user ${who.status}`);
  const user = (await who.json()) as { login: string; id: number };
  const self = user.id === adminCtx.adminUserId;
  return {
    verdict: self ? "self" : "other",
    scope: "user",
    adminCanBill: self,
    confidence: "high",
    tokenKind: kind,
    reason: self ? `user token for ${user.login} (admin)` : `user token for ${user.login}`,
  };
}

function classifyByPrefix(s: string): GitHubOwnership["tokenKind"] {
  if (s.startsWith("ghp_")) return "pat-classic";
  if (s.startsWith("github_pat_")) return "pat-fine-grained";
  if (s.startsWith("gho_")) return "oauth-access";
  if (s.startsWith("ghu_")) return "oauth-user-to-server";
  if (s.startsWith("ghs_")) return "installation";
  if (s.startsWith("ghr_")) return "refresh";
  // GitHub Actions token is a JWT-like opaque without ghX_ prefix in recent versions.
  if (/^ghb_|^ghac_/.test(s) || s.length > 60) return "actions";
  return "unknown";
}

function ghHeaders(token: string) {
  return {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${token}`,
    "X-GitHub-Api-Version": "2022-11-28",
  };
}
```

Pre-populate `adminCtx.adminInstallations` via one call to `GET /user/installations` at `rotate doctor` start. Cache.

## Edge cases

- **PATs cannot be listed via API (security feature).** GitHub intentionally does not expose "list all my PATs" over REST — admin must manage them at `github.com/settings/tokens`. This means: ownership works per-token via `GET /user`, but rotate-cli cannot enumerate unknown PATs or detect "leaked" ones programmatically. Document PATs as `manual-assist` rotation.
- **Fine-grained PATs (`github_pat_*`) scoped to org resources.** `GET /user` still returns the PAT owner (the human user), but the PAT's effective authority is org-resource-scoped. Billing control: NO — PAT can't self-bill anything. Ownership verdict: self/other based on user match; `adminCanBill: false` always.
- **Installation tokens expire in 1h.** If rotate-cli persists a `ghs_*` anywhere (Vercel env, `.env`, Doppler), it's almost certainly stale. Verdict `unknown` with reason `"likely expired"` if detection fails. Cross-reference `created_at` from the secret's rotate-cli metadata — if > 1h, don't even call `/installation/repositories`.
- **`ghs_` from `adapter-github-token` is mint-only.** This adapter only mints new installation tokens; it never receives an existing `ghs_*` to introspect. Ownership is implicit: the token was just minted from an `installation_id` the admin already authenticated against. The ownership check is redundant here but still worth emitting for provenance.
- **Cross-org installations.** A GitHub App can be installed on multiple orgs/users. Each installation has a distinct `installation_id`. Two `ghs_*` tokens with identical-looking suffixes can still belong to different orgs. Always match by `installation_id`, never by token value.
- **OAuth Apps vs GitHub Apps confusion.** `gho_` = OAuth App user access token (long-lived, refreshable). `ghu_` = GitHub App user-to-server token (short-lived, refreshable). Both look similar in casual logs. Detection rule: check the minting app's class via `POST /applications/{client_id}/token` (OAuth App) or via the companion JWT (GitHub App).
- **SSO-enforced orgs.** If a PAT or OAuth token belongs to admin but hasn't been SSO-authorized for a specific org, `GET /user` succeeds but org-resource calls 403. Ownership detection still returns `"self"` correctly — the SSO gate is a separate concern.
- **Token leak feedback loop.** GitHub auto-revokes tokens pushed to public repos (secret scanning). A `401` on ownership check might mean "I just leaked it and GitHub killed it". Rotate-cli should message this specifically if recent activity log shows `leaked` flag — though the REST endpoint for that (`/user/tokens/leaked`) is not public; use the `secret-scanning` webhook on the admin's org if available.
- **GitHub Enterprise Server (GHES).** All endpoints above exist at the GHES host. Rotate-cli must respect `GITHUB_API_URL` / `GH_HOST` env vars (already in `adapter-github-token/src/index.ts`).
- **Rate limits.** `GET /user` and `GET /installation/repositories` are 5000/hr authenticated. `GET /user/installations` same bucket. Ownership scans on a large secret pool could saturate; batch and cache.
- **Admin org ownership vs membership.** For `ghs_*` owned by an organization installation, `adminCanBill` requires admin to be an **org owner** (or have "manage billing" permission). Detect via `GET /orgs/{org}/memberships/{admin-username}` — `role === "admin"` means org owner. Don't assume "admin can see the installation" implies "admin can rotate its auth".

## Sources

- [Behind GitHub's new authentication token formats](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/)
- [GitHub REST API — Apps](https://docs.github.com/en/rest/apps/apps)
- [GitHub REST API — Installations](https://docs.github.com/en/rest/apps/installations)
- [Authenticating as a GitHub App installation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
- [Fine-grained PATs beta](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
