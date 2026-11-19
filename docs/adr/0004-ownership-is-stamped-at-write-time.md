# ADR 0004: Ownership is stamped at write time

Status: accepted

## Context

A scope rule such as "the agency's bookings" or "bookings written by internal staff" needs to know who owns a row.
Computing that from the creator's *current* role is tempting and wrong: when someone is promoted, moved to another
agency or deactivated, every booking they ever made would jump to another scope. Historical data would change
visibility because of an unrelated edit to a user.

## Decision

`Booking` carries its ownership as facts written once: `TenantId`, `OwnerUserId`, `OwnerRoleFamilyAtCreation`,
`AgencyId` and `CorporateId`. They are produced by `OwnershipStamper` from the caller at creation and are never taken
from the request body. Agency and corporate ids are stamped only for the matching family, and an agency or corporate
principal without its account cannot create bookings (403), because the booking would be invisible to its creator.
Scope strategies read these columns and never look at the owner's current role.

## Consequences

- A role change after creation does not move historical bookings between scopes. A test promotes an agency user into the
  internal family and checks that the booking stays with the agency and is invisible to internal staff.
- New bookings from the same user get the new family, so the history shows when responsibility changed.
- Corrections need an explicit data operation (re-stamping), not a side effect of editing a user. That is the point, but it
  means support staff need a tool for it.
- Guest bookings have no staff family. Their visibility follows the account fields they carry.
