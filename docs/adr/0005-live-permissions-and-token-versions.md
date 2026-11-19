# ADR 0005: Permissions are resolved live, sessions are revoked with token versions

Status: accepted

## Context

Putting permissions inside the token is cheap and wrong for an RBAC system: an edit to a role or a user has no effect
until the token expires, and a user who is deactivated keeps working. Looking everything up on every request fixes that
but gives no way to end a session that already carries an old role.

## Decision

- The token carries identity only: subject, tenant, role key, account ids and a token version. Authorization decisions
  use **effective permissions read from the database on each request** (resolved once per request and shared by the
  policy handler and the endpoint): role defaults, plus per-user grants, minus per-user revokes. A stored user that is
  missing, inactive, of a different kind, or whose stored role differs from the token's role has no permissions.
- `ITokenVersionStore` holds the current version per user. The JWT bearer events reject a token whose version differs from
  the current one (401). Editing a role or user and bumping the version therefore revokes existing sessions, and the next
  token issued carries the new version.
- A token that lacks a subject, tenant or version is rejected as a 401 before any permission check.

## Consequences

- Permission edits are effective on the next request. A test revokes a permission, adds a grant, edits a role default and
  deactivates a user while holding the same token.
- Resolving permissions costs a few small queries. They are cached per principal and validated against a persisted per-tenant
  epoch on every request, so a second instance never serves stale permissions (ADR 0010).
- Token versions live in the database (one atomic upsert per bump), so a restart or a second instance never forgets a revocation.
  An in-memory implementation remains for unit tests. The version check is a direct read and is not cached.
- Revocation is by version, not by token: bumping a user's version ends all of that user's sessions at once.
