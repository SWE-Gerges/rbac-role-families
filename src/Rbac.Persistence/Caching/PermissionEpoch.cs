using Microsoft.EntityFrameworkCore;
using Rbac.Persistence.Entities;

namespace Rbac.Persistence.Caching;

/// <summary>
/// The persisted per-tenant permission epoch: a counter that every permission, role default and per-user permission write
/// increments in the same transaction as the write. Caches stamp what they hold with the epoch they read first and compare
/// it with the current one on each request, which is how a second application instance learns that something changed.
/// A tenant without a row is on epoch 0. Writes that bypass the application (an operator editing rows) must bump the epoch
/// too, or caches keep serving what they already hold.
/// </summary>
public static class PermissionEpoch
{
    /// <summary>One indexed single-row read by primary key.</summary>
    public static async Task<long> ReadAsync(RbacDbContext db, string tenantId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);
        return await db.PermissionEpochs
            .AsNoTracking()
            .Where(e => e.TenantId == tenantId)
            .Select(e => (long?)e.Epoch)
            .SingleOrDefaultAsync(cancellationToken) ?? 0;
    }

    /// <summary>Increments one tenant's epoch with a single atomic upsert, inside whatever transaction the context has open.</summary>
    public static async Task BumpAsync(RbacDbContext db, string tenantId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);
        await db.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO "PermissionEpoch" ("TenantId", "Epoch") VALUES ({tenantId}, 1)
            ON CONFLICT ("TenantId") DO UPDATE SET "Epoch" = "PermissionEpoch"."Epoch" + 1
            """,
            cancellationToken);
    }

    /// <summary>
    /// Increments the epoch of every tenant, for changes that are not owned by one tenant (role structure at a catalog upgrade). It upserts from the
    /// tenant table so a tenant that has no epoch row yet is not skipped.
    /// </summary>
    public static async Task BumpAllAsync(RbacDbContext db, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);
        await db.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO "PermissionEpoch" ("TenantId", "Epoch") SELECT "Id", 1 FROM "Tenant" WHERE true
            ON CONFLICT ("TenantId") DO UPDATE SET "Epoch" = "PermissionEpoch"."Epoch" + 1
            """,
            cancellationToken);
    }
}
