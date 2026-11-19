using Microsoft.EntityFrameworkCore;
using Rbac.Persistence.Caching;

namespace Rbac.Persistence.Administration;

/// <summary>
/// What every permission-affecting write must also do, inside the same transaction as the write: revoke the sessions of
/// the users it touches and move the permission epoch so caches (in this process and in every other instance) refresh.
/// Keeping both in one place means a new write path cannot remember one and forget the other.
/// </summary>
internal static class PermissionChangeEffects
{
    /// <summary>One user's permissions, role or existence changed.</summary>
    public static async Task UserChangedAsync(RbacDbContext db, string tenantId, string userId, CancellationToken cancellationToken)
    {
        await DbTokenVersionStore.BumpAsync(db, tenantId, userId, cancellationToken);
        await PermissionEpoch.BumpAsync(db, tenantId, cancellationToken);
    }

    /// <summary>
    /// The default permissions of a role changed in one tenant. Only that tenant is affected: every live holder of the role there has
    /// their sessions revoked and their permission version moved, and only that tenant's epoch moves.
    /// </summary>
    public static async Task RoleDefaultsChangedAsync(RbacDbContext db, string tenantId, string roleKey, CancellationToken cancellationToken)
    {
        await db.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO "TokenVersion" ("TenantId", "UserId", "Version")
            SELECT "TenantId", "Id", 2 FROM "User" WHERE "TenantId" = {tenantId} AND "RoleKey" = {roleKey} AND "DeletedAt" IS NULL
            ON CONFLICT ("TenantId", "UserId") DO UPDATE SET "Version" = "TokenVersion"."Version" + 1
            """,
            cancellationToken);

        await db.Users
            .IgnoreQueryFilters()
            .Where(u => u.TenantId == tenantId && u.RoleKey == roleKey && u.DeletedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.PermissionsVersion, u => u.PermissionsVersion + 1), cancellationToken);

        await PermissionEpoch.BumpAsync(db, tenantId, cancellationToken);
    }
}
