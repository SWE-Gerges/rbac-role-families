# ADR 0003: Deny by default, and fail at startup instead of resolving by order

Status: accepted

## Context

Authorization configuration has two failure modes that are expensive because they look like working software:
an endpoint nobody gated that is open to everyone, and a role or family nobody wired up that silently falls through to
a broader strategy. Order-dependent resolution (first matching strategy wins) makes the second one worse, because
the outcome depends on how the container happened to register things.

## Decision

- **Endpoints**: ASP.NET Core's `FallbackPolicy` requires an authenticated user for every endpoint that does not carry
  other authorization metadata. Only health checks and the dev token issuer opt out with `[AllowAnonymous]`; a test lists
  the anonymous endpoints and fails if the list changes. Gated actions use `[RequirePermission("...")]`, which builds
  policies on demand through an `IAuthorizationPolicyProvider`. A missing permission is a 403, a missing or revoked
  token is a 401.
- **Data**: the resolver's last resort is `NoAccessScope` (`_ => false`). An anonymous caller, an unknown role, a
  family without a strategy, a family registered twice, and a principal without the agency or corporate account its
  family needs all end up there or return no rows.
- **Wiring**: `RbacStartupValidator` is a hosted service that throws before the host serves requests when a role has no
  family, a family does not have exactly one strategy, a strategy is registered for an undefined family, two roles share
  a key, or a creatable role key does not exist. It reports every problem at once. It is registered before the database
  initializer so misconfiguration is found first.

## Consequences

- A forgotten gate or a forgotten strategy is a failed deployment or a denied request, never a silent grant.
- Adding a family means touching the enum, the registry and the validator's expectations in one change; the host will not
  start until it is complete.
- Strictness has a cost: a new anonymous endpoint needs a deliberate edit to the allow-list test, and unknown routes
  answer 401 to anonymous callers instead of 404.
