using Microsoft.EntityFrameworkCore;
using Rbac.Abstractions;
using Rbac.Core.Catalog;
using Rbac.Persistence.Caching;
using Rbac.Persistence.Entities;

namespace Rbac.Persistence.Seeding;

/// <param name="PermissionsAdded">Permission definitions that were new.</param>
/// <param name="PermissionsUpdated">Permission definitions whose description changed.</param>
/// <param name="RolesAdded">Roles that were new.</param>
/// <param name="RolesUpdated">Roles whose structure was brought in line with a newer catalog version.</param>
/// <param name="DefaultsAdded">Role defaults handed out for the first time, counted per tenant.</param>
public sealed record PermissionSeedResult(int PermissionsAdded, int PermissionsUpdated, int RolesAdded, int RolesUpdated, int DefaultsAdded)
{
    public bool Changed => PermissionsAdded + PermissionsUpdated + RolesAdded + RolesUpdated + DefaultsAdded > 0;
}

/// <summary>
/// Brings the stored permission catalog in line with the code-defined one. It is safe to run on every start: a second run
/// changes nothing. Rules:
/// <list type="bullet">
/// <item>Permission definitions and role structure are global. Definitions are upserted by key; missing roles are added.</item>
/// <item>Role defaults belong to a tenant. Every tenant gets its own copy of the catalog's defaults, so an administrator's edit
/// never reaches another tenant. A tenant that has none yet (a brand-new one) gets all of them the next time the seeder runs,
/// or immediately through <see cref="SeedTenantAsync"/>; until then its users have no permissions, which is the deny-by-default
/// answer.</item>
/// <item>A role default is handed out once per tenant. The (tenant, role, permission) triple is recorded as seeded in a catalog
/// version, and a recorded triple is never added again, so a permission an administrator removed from a role stays removed.</item>
/// <item>A permission an administrator added to a role is never removed, and per-user overrides are never touched.</item>
/// <item>The structure of an existing role (family, creatable roles, admin tier, order) follows the code only when the code
/// catalog version is higher than the one last applied. With equal versions a stored role is left as it is, so a bad
/// stored value is reported by startup validation instead of being quietly repaired.</item>
/// </list>
/// When anything changes, the permission epoch of each affected tenant moves in the same transaction so caches refresh.
/// </summary>
public static class PermissionSeeder
{
    public static async Task<PermissionSeedResult> SeedAsync(RbacDbContext db, RoleCatalog catalog, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(catalog);

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var applied = await db.CatalogVersions.SingleOrDefaultAsync(v => v.Name == CatalogVersionEntity.RoleCatalogName, cancellationToken);
        var upgrading = catalog.Version > (applied?.Version ?? 0);

        var permissionsAdded = 0;
        var permissionsUpdated = 0;
        var stored = await db.Permissions.ToDictionaryAsync(p => p.Key, StringComparer.Ordinal, cancellationToken);
        var wanted = catalog.Roles.SelectMany(r => r.DefaultPermissions)
            .Concat(Permissions.All)
            .Concat(Permissions.CustomerDefaults)
            .Distinct(StringComparer.Ordinal);
        foreach (var key in wanted)
        {
            var description = Permissions.Describe(key);
            if (!stored.TryGetValue(key, out var permission))
            {
                db.Permissions.Add(new PermissionEntity { Key = key, Description = description });
                permissionsAdded++;
            }
            else if (permission.Description != description)
            {
                permission.Description = description;
                permissionsUpdated++;
            }
        }

        var rolesAdded = 0;
        var rolesUpdated = 0;
        var roles = await db.Roles.ToDictionaryAsync(r => r.Key, StringComparer.Ordinal, cancellationToken);
        var order = 0;
        foreach (var role in catalog.Roles)
        {
            order++;
            if (!roles.TryGetValue(role.Key, out var entity))
            {
                db.Roles.Add(new RoleEntity { Key = role.Key, Family = role.Family, CreatableRoleKeys = [.. role.CreatableRoleKeys], SortOrder = order, IsAdmin = role.IsAdmin });
                rolesAdded++;
            }
            else if (upgrading && !StructureMatches(entity, role, order))
            {
                entity.Family = role.Family;
                entity.CreatableRoleKeys = [.. role.CreatableRoleKeys];
                entity.SortOrder = order;
                entity.IsAdmin = role.IsAdmin;
                rolesUpdated++;
            }
        }

        // Permissions and roles must exist before the rows that point at them, so they are saved first.
        await db.SaveChangesAsync(cancellationToken);

        var tenantIds = await db.Tenants.AsNoTracking().Select(t => t.Id).ToListAsync(cancellationToken);
        var state = await LoadStateAsync(db, cancellationToken);
        var changedTenants = new List<string>();
        var defaultsAdded = 0;
        foreach (var tenantId in tenantIds)
        {
            var added = AddMissingDefaults(db, tenantId, catalog, state);
            if (added > 0)
            {
                defaultsAdded += added;
                changedTenants.Add(tenantId);
            }
        }

        if (applied is null)
        {
            db.CatalogVersions.Add(new CatalogVersionEntity { Name = CatalogVersionEntity.RoleCatalogName, Version = catalog.Version });
        }
        else if (upgrading)
        {
            applied.Version = catalog.Version;
        }

        var result = new PermissionSeedResult(permissionsAdded, permissionsUpdated, rolesAdded, rolesUpdated, defaultsAdded);
        await db.SaveChangesAsync(cancellationToken);

        if (rolesUpdated > 0)
        {
            await PermissionEpoch.BumpAllAsync(db, cancellationToken);
        }
        else
        {
            foreach (var tenantId in changedTenants)
            {
                await PermissionEpoch.BumpAsync(db, tenantId, cancellationToken);
            }
        }

        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    /// <summary>
    /// Gives one tenant the role defaults of the catalog that it does not have yet, with the same rules as <see cref="SeedAsync"/>.
    /// Use it when a tenant is created while the host is running. The permissions and roles must already be stored, which
    /// <see cref="SeedAsync"/> does at startup.
    /// </summary>
    public static async Task<PermissionSeedResult> SeedTenantAsync(RbacDbContext db, string tenantId, RoleCatalog catalog, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        ArgumentNullException.ThrowIfNull(catalog);

        if (!await db.Tenants.AnyAsync(t => t.Id == tenantId, cancellationToken))
        {
            throw new InvalidOperationException($"Tenant '{tenantId}' does not exist.");
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var state = await LoadStateAsync(db, cancellationToken, tenantId);
        var added = AddMissingDefaults(db, tenantId, catalog, state);
        await db.SaveChangesAsync(cancellationToken);
        if (added > 0)
        {
            await PermissionEpoch.BumpAsync(db, tenantId, cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return new PermissionSeedResult(0, 0, 0, 0, added);
    }

    private sealed record SeedState(
        HashSet<(string Tenant, string Role, string Permission)> Seeded,
        HashSet<(string Tenant, string Role, string Permission)> Granted);

    private static async Task<SeedState> LoadStateAsync(RbacDbContext db, CancellationToken cancellationToken, string? tenantId = null)
    {
        var seeds = db.RoleDefaultSeeds.AsNoTracking();
        var granted = db.RolePermissions.IgnoreQueryFilters().AsNoTracking();
        if (tenantId is not null)
        {
            seeds = seeds.Where(s => s.TenantId == tenantId);
            granted = granted.Where(rp => rp.TenantId == tenantId);
        }

        return new SeedState(
            (await seeds.Select(s => new { s.TenantId, s.RoleKey, s.PermissionKey }).ToListAsync(cancellationToken))
                .Select(s => (s.TenantId, s.RoleKey, s.PermissionKey)).ToHashSet(),
            (await granted.Select(rp => new { rp.TenantId, rp.RoleKey, rp.PermissionKey }).ToListAsync(cancellationToken))
                .Select(rp => (rp.TenantId, rp.RoleKey, rp.PermissionKey)).ToHashSet());
    }

    private static int AddMissingDefaults(RbacDbContext db, string tenantId, RoleCatalog catalog, SeedState state)
    {
        var added = 0;
        foreach (var role in catalog.Roles)
        {
            foreach (var permission in role.DefaultPermissions.Order(StringComparer.Ordinal))
            {
                if (state.Seeded.Contains((tenantId, role.Key, permission)))
                {
                    continue;
                }

                db.RoleDefaultSeeds.Add(new RoleDefaultSeedEntity { TenantId = tenantId, RoleKey = role.Key, PermissionKey = permission, SeededInVersion = catalog.Version });
                if (!state.Granted.Contains((tenantId, role.Key, permission)))
                {
                    db.RolePermissions.Add(new RolePermissionEntity { TenantId = tenantId, RoleKey = role.Key, PermissionKey = permission });
                    added++;
                }
            }
        }

        return added;
    }

    private static bool StructureMatches(RoleEntity entity, RoleDefinition role, int order) =>
        entity.Family == role.Family
        && entity.IsAdmin == role.IsAdmin
        && entity.SortOrder == order
        && entity.CreatableRoleKeys.SequenceEqual(role.CreatableRoleKeys);
}
