# ADR 0010: Cached permissions are validated against a persisted per-tenant epoch

Status: accepted

## Context

Permissions are resolved live (ADR 0005), which costs a few queries on every request. Caching them is easy; knowing when a
cached answer is no longer true is the hard part, and it gets harder with more than one application instance, because an instance
cannot see another instance's writes.

## Decision

- Each tenant has a persisted **epoch**, a counter. Every permission, role default and per-user permission write increments it in
  the same transaction as the write. Role defaults belong to a tenant, so editing one increments only that tenant's epoch. A change that is not
  owned by one tenant (role structure at a catalog upgrade) increments every tenant's epoch, upserting from the tenant table so a
  tenant with no epoch row yet is not skipped.
- A caching decorator over the permission store keeps resolved permissions in process, bounded, keyed by tenant, user, kind and
  role. Each entry carries the epoch it was resolved under. On every request that needs permissions the decorator reads the tenant's
  epoch and compares: equal is a hit, different is a miss that resolves again.
- The epoch is read **before** the permissions are resolved and stamped on the entry. A write that lands in between leaves the
  entry with the older epoch, so the next request refreshes it. A cached answer is never newer than its stamp.
- No external cache server is needed. Hits, misses, invalidations and epoch reads are counted.

## Consequences

- Cost: one primary-key read of a single row per request, against three queries for a miss. The cache saves work only when the
  epoch rarely moves, and a request never serves permissions older than the last epoch it read.
- A second instance sees a change on its next request. The tests run two hosts over one SQLite file, check the warm hit and the
  miss after a write, and include a control: a raw database edit that does not move the epoch stays invisible to a warm instance.
- **Writes that bypass the application must move the epoch too.** That is the contract, and the seeder and the administration
  code do it through one helper.
- Caching can be turned off with `Persistence:CachePermissions=false`, which reads permissions from the database on every request.
- Token versions are not cached: the revocation check stays a direct read.
