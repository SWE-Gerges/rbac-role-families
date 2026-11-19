using Microsoft.EntityFrameworkCore;
using Rbac.Abstractions;
using Rbac.Core.Catalog;
using Rbac.Persistence.Entities;

namespace Rbac.Persistence;

/// <summary>
/// Resolves effective permissions from the database on every call: the role defaults, plus per-user grants,
/// minus per-user revokes. A token's role or kind that no longer matches the stored user resolves to nothing.
/// </summary>
public sealed class DbPermissionStore(RbacDbContext db) : IPermissionStore
{
    public async ValueTask<PermissionSet> GetEffectivePermissionsAsync(Principal principal, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (principal.IsAnonymous)
        {
            return PermissionSet.Empty;
        }

        // Keyed by the principal, not by the ambient tenant context, so the answer never depends on who else is in scope.
        var user = await db.Users
            .IgnoreQueryFilters()
            .AsNoTracking()
            .Where(u => u.Id == principal.UserId && u.TenantId == principal.TenantId && u.DeletedAt == null)
            .Select(u => new { u.Kind, u.RoleKey, u.IsActive })
            .SingleOrDefaultAsync(cancellationToken);

        if (user is null || !user.IsActive || user.Kind != principal.Kind)
        {
            return PermissionSet.Empty;
        }

        IEnumerable<string> defaults;
        if (principal.Kind == PrincipalKind.Customer)
        {
            defaults = Permissions.CustomerDefaults;
        }
        else
        {
            if (string.IsNullOrEmpty(user.RoleKey) || user.RoleKey != principal.RoleKey)
            {
                return PermissionSet.Empty;
            }

            // The defaults of the principal's own tenant, named explicitly like the user lookup above.
            defaults = await db.RolePermissions
                .IgnoreQueryFilters()
                .AsNoTracking()
                .Where(rp => rp.TenantId == principal.TenantId && rp.RoleKey == user.RoleKey)
                .Select(rp => rp.PermissionKey)
                .ToListAsync(cancellationToken);
        }

        var overrides = await db.UserPermissions
            .IgnoreQueryFilters()
            .AsNoTracking()
            .Where(up => up.UserId == principal.UserId && up.TenantId == principal.TenantId)
            .Select(up => new { up.PermissionKey, up.Effect })
            .ToListAsync(cancellationToken);

        var effective = new HashSet<string>(defaults, StringComparer.Ordinal);
        effective.UnionWith(overrides.Where(o => o.Effect == PermissionEffect.Grant).Select(o => o.PermissionKey));
        effective.ExceptWith(overrides.Where(o => o.Effect == PermissionEffect.Revoke).Select(o => o.PermissionKey));
        return PermissionSet.Create(effective);
    }
}
