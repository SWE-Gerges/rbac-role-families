# ADR 0006: Out of scope is a 404, a missing permission is a 403

Status: accepted

## Context

For a by-id request there are two different questions. "May this caller use this *kind of operation*?" is about the
caller's permissions. "May this caller see *this particular row*?" is about the data scope. Answering the second one with
403 confirms that the id exists, which lets a caller enumerate other tenants' and other agencies' bookings.

## Decision

- A permission the caller does not hold is a **403** (`bookings.read`, `bookings.cancel`, `access-matrix.view`, ...). It
  says nothing about any particular row.
- A booking outside the caller's scope is a **404**, with the same problem document as a booking that does not exist.
  A test compares the two responses field by field.
- The order for an action such as cancel is: authentication (401), permission (403), scope (404), state (409).
- The channel header some clients send (web, app, back-office) is never an authorization input. The demo echoes a known
  value back as a presentation hint and a test shows that results and denials are identical with any value.

## Consequences

- Ids cannot be probed across scopes or tenants.
- A legitimate caller who mistypes an id and a caller who is not allowed to see it get the same answer, which makes
  support slightly harder. The correlation id in every problem document lets support look the request up in the logs.
- Clients must not treat 404 as proof that a booking does not exist anywhere.
