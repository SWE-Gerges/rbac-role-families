# ADR 0007: Who may create whom is data, enforced per family, with a founding admin per account

Status: accepted

## Context

User management has three questions that are easy to blur: which users a caller can see, which roles they may create or assign,
and what they may do to a user they can see. Hard-coded `if (role == ...)` chains answer them inconsistently, an agency admin
who can mint more agency admins makes the account's control unrecoverable, and "admin" must not mean "can delete the first admin".

## Decision

- `RoleDefinition.CreatableRoleKeys` is the creation graph. It is stored data, validated at startup (every entry must be a defined
  role) like everything else in the catalog. Privilege is derived from it: a role outranks the roles reachable from it, never itself.
- What a caller may do to a visible user is decided by an `IRoleManagementStrategy`, chosen per role family from an explicit
  registry with the same startup validation as the scope strategies (one per family, no order-dependent selection, a deny-all
  fallback). Which users are visible at all is a separate question answered by `IAccessScopeStrategy<User>`, so user lists and
  by-id lookups share one predicate and an invisible user is a 404.
- System and internal admins act across the accounts of their tenant. Agency and corporate admins act inside their own account
  only. Nobody crosses tenants: the tenant is the caller's and cannot be named in a request.
- Each agency or corporate account has one founding admin (the first admin created for it, enforced by a unique index among live
  users). Only the founding admin, an internal admin or a system admin creates or promotes further admins; other admins create
  staff only. Nobody inside the account can delete or demote the founding admin; internal and system admins can, and the next
  admin created for that account becomes its founder.
- Role changes and deletes bump the user's token version in the same transaction, so a change never leaves a live session behind.

## Consequences

- A new role family needs a management strategy or the host does not start.
- The rules are testable as a table (caller role by target role by account relation), and the expected statuses are written from
  the rules rather than from the code that implements them.
- The founding admin is a flag on the user, not a role, so a promotion, demotion or replacement needs no catalog change.
