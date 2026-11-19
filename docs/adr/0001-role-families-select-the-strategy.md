# ADR 0001: Role families are the unit of strategy selection

Status: accepted

## Context

A booking platform has many roles (`agency-admin`, `agency-staff`, `corporate-admin`, ...) and each decides what
data a caller may see. Two designs are common and both age badly:

- one big `switch` on the role key in every query, which is copied into every list, dashboard and lookup;
- a list of strategies where the first one whose `Supports(role)` returns true wins, which depends on registration
  order and silently changes behaviour when a strategy is added.

Roles also come and go. What changes slowly is *how* a group of roles relates to the data: an agency's people see the
agency's bookings, a corporate account's people see the account's bookings, internal staff see internal bookings.

## Decision

Every staff role belongs to exactly one **role family** (`System`, `Finance`, `Internal`, `Corporate`, `Agency`,
`Viewer`). The scope strategy is chosen per family from an explicit `StrategyRegistry`
(`RoleFamily -> IAccessScopeStrategy<Booking>`): the resolver reads the caller's role, looks up the role's family in the
catalog, and looks the family up in the registry. Role keys are defined once (`RoleKeys`) and roles come from one
`RoleCatalog`, which can be built in code and is also stored in the Role, Permission and RolePermission tables.

Customers and anonymous callers are not a staff family. They are a separate `PrincipalKind` (`Customer`, `Anonymous`)
with their own strategies, so a missing or unknown role can never be mistaken for "the customer role".

## Consequences

- Adding a role to an existing family needs no new strategy; adding a family forces a registry entry, and startup
  validation refuses to boot without one (see ADR 0003).
- Within a family, differences between roles are expressed inside the strategy (for example `agency-admin` versus
  `agency-staff` with or without `bookings.view-all-agency`), which keeps each rule in one readable place.
- A role that must behave unlike its family has to move to another family or get a new one. That is deliberate friction.
- The staff/customer split costs one extra branch in the resolver and removes a whole class of privilege-confusion bugs.
