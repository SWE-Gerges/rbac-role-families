using Microsoft.EntityFrameworkCore;
using Rbac.Abstractions;
using Rbac.Core.Catalog;

namespace Rbac.Persistence;

/// <summary>
/// Loads the role catalog from the Role and RolePermission tables. Role structure (key, family, creation graph, admin tier) is global;
/// default permissions belong to a tenant. Writing is the job of <see cref="Seeding.PermissionSeeder"/> and the administration API.
/// </summary>
public static class RoleCatalogStore
{
    /// <summary>
    /// The stored role structure with no default permissions. This is what the host validates and runs on: nothing that decides
    /// access reads a role's defaults from it, because the defaults differ per tenant.
    /// </summary>
    public static async Task<RoleCatalog> LoadStructureAsync(RbacDbContext db, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);

        var roles = await db.Roles.AsNoTracking().OrderBy(r => r.SortOrder).ThenBy(r => r.Key).ToListAsync(cancellationToken);
        return RoleCatalog.FromDefinitions(roles.Select(r => new RoleDefinition(
            r.Key, r.Family, new HashSet<string>(StringComparer.Ordinal), r.CreatableRoleKeys, r.IsAdmin)));
    }

    /// <summary>The stored roles with the default permissions of one tenant. A tenant without defaults yields roles that grant nothing.</summary>
    public static async Task<RoleCatalog> LoadAsync(RbacDbContext db, string tenantId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);

        var roles = await db.Roles.AsNoTracking().OrderBy(r => r.SortOrder).ThenBy(r => r.Key).ToListAsync(cancellationToken);
        var rolePermissions = (await db.RolePermissions
                .IgnoreQueryFilters()
                .AsNoTracking()
                .Where(rp => rp.TenantId == tenantId)
                .ToListAsync(cancellationToken))
            .ToLookup(rp => rp.RoleKey, rp => rp.PermissionKey, StringComparer.Ordinal);

        return RoleCatalog.FromDefinitions(roles.Select(r => new RoleDefinition(
            r.Key,
            r.Family,
            rolePermissions[r.Key].ToHashSet(StringComparer.Ordinal),
            r.CreatableRoleKeys,
            r.IsAdmin)));
    }
}
