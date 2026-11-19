# ADR 0011: Acting on behalf of someone applies their rules, never the actor's

Status: accepted

## Context

Support and administration staff need to see what a user sees and sometimes act for them. The two bad designs are impersonation
that silently grants the actor's own powers on top of the user's, and a header that is ignored when the caller lacks permission, so
the caller believes they are acting as someone and are not.

## Decision

- A caller with `users.act-on-behalf` sends `X-On-Behalf-Of: <userId>`. A middleware resolves it after authentication and before
  authorization and replaces the request's principal with the effective one. From then on every permission check, scope predicate,
  ownership stamp and management rule uses the effective user.
- The actor's permissions are read directly from the permission store to decide whether they may act at all, never through the
  per-request permissions, which must stay those of the effective user.
- Without the permission the answer is 403, even when the target is valid or does not exist: the header is never silently ignored.
- The target must be visible to the actor, so another tenant's users and users outside the actor's account do not exist for
  them (404). A visible target is refused (403) unless the actor strictly outranks them: no peers, no higher roles, no founding
  admin of an account for a plain admin, nobody acting as themselves, and no deactivated users. The founder's authority over peer
  admins does not extend to acting as them.
- `Principal` carries `ActingUserId` and `EffectiveUserId`. Audit entries record both, `GET /api/v1/me` shows who is acting, and
  bookings created on behalf are stamped with the effective user. An unauthenticated request with the header is a 401.
- The client channel header stays a presentation hint and has no say in any of this.

## Consequences

- An actor cannot use the header to do anything the effective user could not do, so the header cannot be used to escalate.
- Anyone who holds the permission can read as, and act as, users below them. The permission is held by system and internal admins
  by default and cannot be granted beyond what the granter holds (ADR 0008).
- The header is documented on every authenticated operation in the OpenAPI document.
