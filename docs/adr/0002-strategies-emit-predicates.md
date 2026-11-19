# ADR 0002: Strategies emit predicates, so lists and by-id lookups share one rule

Status: accepted

## Context

If "who may see this booking" is implemented once as a SQL filter for lists and again as an `if` after loading a row
for by-id requests, the two drift apart. The classic result is an id that is hidden in the list but readable by URL, or
the reverse. Dashboards and exports add a third and fourth copy of the rule.

## Decision

`IAccessScopeStrategy<TResource>` has one method, `Scope(principal, permissions)`, which returns an
`Expression<Func<TResource, bool>>`. It is pure: no database calls, no client-side evaluation, no I/O. The predicate is
applied by `IScopedQuery<TResource>.ScopedFor(...)`, and that is the only way the demo's endpoints read bookings:

- a list is `ScopedFor(...)` plus filters and paging;
- a by-id lookup is `ScopedFor(...).Where(b => b.Id == id)`;
- a narrowed view ("my bookings only") is the `NarrowedScope` decorator, which is the conjunction of the inner
  predicate and an extra one, so narrowing can only reduce visibility.

Tests enforce the contract: the strategies are run against SQLite and must translate to SQL without
client evaluation, a property test checks that a narrowed result is a subset of the inner result, and a test checks that
for every seeded user and booking "in the list" is equivalent to "by-id returns 200". A convention test fails if
endpoint code reads the bookings `DbSet` directly.

## Consequences

- The rule exists exactly once per family. Changing it changes lists, lookups and cancels together.
- Predicates must stay translatable: strategies decide on the principal and permissions in plain C# (outside the
  expression) and only put column comparisons inside it. Calling a helper method inside the expression fails loudly in
  the translation test rather than silently loading the table.
- Rules that need data a predicate cannot reach (for example a call to another service) do not fit this model and would
  need a pre-computed set of ids passed in as a parameter.
