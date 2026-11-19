# ADR 0009: The audit trail is append-only because nothing can change it, not because nobody tries

Status: accepted

## Context

An audit log that application code could edit or delete is a log that someone eventually edits or deletes, by mistake or on
purpose. A log written after the change can also disagree with it: the change commits, the log write fails, and the trail has
a hole.

## Decision

- An entry is `{ Id, TenantId, ActorUserId, EffectiveUserId?, Action, TargetType, TargetId, Before, After, CorrelationId, At }`.
  It is written in the same transaction, and the same `SaveChanges`, as the change it describes, so they succeed or fail together.
- The model has no update or delete path: the entity has init-only properties, the context exposes the table only as a read-only
  query, and entries are added through one service.
- An EF `SaveChanges` interceptor, registered by the context itself so no construction path can skip it, throws before saving when
  a tracked entry is modified or deleted. Nothing else in that unit of work is written either.
- Set-based statements (`ExecuteUpdate`, `ExecuteDelete`, raw SQL) never reach the change tracker, so the database refuses them:
  SQLite triggers reject UPDATE and DELETE, and a Postgres migration adds triggers that also reject TRUNCATE.
- `GET /api/v1/audit` needs `audit.view`, is limited to the caller's tenant by the global filter, and filters by target and actor.
- Both ids are recorded when someone acts on behalf of another user (ADR 0011).

## Consequences

- The SQLite behaviour is covered by tests (interceptor, triggers, atomicity with a deliberately failing audit insert). The Postgres
  trigger migration is committed but has not been run against a Postgres server in this repository.
- A database owner can still drop the triggers. This is protection against application code and accidents, not against a
  privileged operator, and the entries are not tamper-evident (no hash chain).
- Bookings are not audited; the trail covers user, role and permission administration.
