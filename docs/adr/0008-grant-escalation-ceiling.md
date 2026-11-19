# ADR 0008: Callers can only hand out what they hold

Status: accepted

## Context

An API that lets administrators edit permissions has a classic hole: a caller sends a permission list and the server stores it.
Any administrator can then grant themselves, or an accomplice, something they never had. Permission edits also have to survive two
people editing the same user at once.

## Decision

- **Ceiling.** A caller may grant, revoke or reset a permission only if they currently hold it effectively (role defaults plus
  their own overrides, resolved live). Revoking is held to the same bar as granting. A list supplied by the client is checked
  against the ceiling and never trusted. The same rule applies when a system admin edits a role's defaults.
- **Reserved permissions.** The permission that edits role defaults cannot be granted, revoked or added to a role through the API,
  only held through a role definition. That removes the delegation path and the lock-out path in one rule.
- **Scope.** Per-user edits additionally need the target to be visible to the caller (otherwise 404) and the management rule to
  allow it (otherwise 403). Nobody edits their own permissions.
- **Diff semantics.** An edit is `grant`, `revoke` and `reset` lists. Overrides are stored minimally: only what differs from
  the role default, so repeating a diff changes nothing, and a diff that changes nothing bumps no version, revokes no session and
  writes no audit entry.
- **Lost updates.** `GET .../permissions` returns a version (also as an `ETag`). `PUT` needs it as `If-Match`: 428 when missing,
  412 when stale. The check is a compare-and-swap inside the write transaction, so two editors cannot both win.
- Every change revokes the sessions of the users it touches, writes an audit entry and moves the permission epoch, in one transaction.
- Role defaults belong to a tenant. A role definition (key, family, creation graph) is global and cannot be edited through the
  API, but what the role grants by default is each tenant's own copy, so an edit changes only the caller's tenant: that tenant's
  holders of the role have their sessions revoked, that tenant's epoch moves and the audit entry lands in that tenant. There is no
  parameter that names another tenant, and every read and write of defaults carries the caller's tenant.

## Consequences

- The permission that edits role defaults cannot be removed from the system role through the API, so the API cannot lock itself out; only a direct database edit can.
- A system admin cannot give a role a permission the system role does not hold, even though they could edit the catalog by hand.
  That is deliberate: the ceiling is about what the caller is, not what the API could technically store.
- Precedence of refusals is fixed and documented: visibility (404), validation (400), management rule (403), ceiling (403),
  precondition (428 or 412).
