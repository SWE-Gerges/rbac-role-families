using Microsoft.EntityFrameworkCore;
using Rbac.Abstractions;
using Rbac.Core.Management;
using Rbac.Core.Users;

namespace Rbac.Persistence.Administration;

/// <summary>What every management operation needs first: the target as the caller may see it, and the caller as the rules see them.</summary>
public sealed class ManagementSupport(
    RbacDbContext db,
    IScopedQuery<User> users,
    ICurrentPermissions permissions,
    IRoleCatalog catalog)
{
    /// <summary>Loads a user through the caller's scope. Out of scope and missing are the same answer (null).</summary>
    public async Task<User?> FindVisibleAsync(Principal principal, string id, bool track, CancellationToken cancellationToken)
    {
        var granted = await permissions.GetAsync(cancellationToken);
        var query = users.ScopedFor(principal, granted).Where(u => u.Id == id);
        return await (track ? query : query.AsNoTracking()).FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<ManagementActor?> ResolveActorAsync(Principal principal, CancellationToken cancellationToken)
    {
        if (principal.Kind != PrincipalKind.Staff || catalog.Find(principal.RoleKey) is not { } role)
        {
            return null;
        }

        var founder = await db.Users
            .AsNoTracking()
            .Where(u => u.Id == principal.UserId)
            .Select(u => u.IsFoundingAdmin)
            .FirstOrDefaultAsync(cancellationToken);
        return new ManagementActor(principal, role, founder);
    }

    public static ManagedUser ToManaged(User user) =>
        new(user.Id, user.TenantId, user.Kind, user.RoleKey, user.AgencyId, user.CorporateId, user.IsFoundingAdmin);
}
