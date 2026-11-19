using System.Linq.Expressions;
using Rbac.Abstractions;
using Rbac.Core.Scopes;

namespace Rbac.Core.Users;

/// <summary>Every user in the caller's tenant.</summary>
public sealed class SystemUserScope : IAccessScopeStrategy<User>
{
    public string Name => nameof(SystemUserScope);

    public Expression<Func<User, bool>> Scope(Principal principal, PermissionSet permissions)
    {
        if (!ScopeGuard.IsStaffInTenant(principal))
        {
            return ScopeGuard.None<User>();
        }

        var tenantId = principal.TenantId;
        return u => u.TenantId == tenantId;
    }
}

/// <summary>Every user in the caller's tenant except members of the system family, who are out of reach of internal staff.</summary>
public sealed class InternalUserScope(IRoleCatalog catalog) : IAccessScopeStrategy<User>
{
    public string Name => nameof(InternalUserScope);

    public Expression<Func<User, bool>> Scope(Principal principal, PermissionSet permissions)
    {
        if (!ScopeGuard.IsStaffInTenant(principal))
        {
            return ScopeGuard.None<User>();
        }

        var tenantId = principal.TenantId;
        var systemRoleKeys = catalog.Roles.Where(r => r.Family == RoleFamily.System).Select(r => r.Key).ToArray();
        return u => u.TenantId == tenantId && (u.RoleKey == null || !systemRoleKeys.Contains(u.RoleKey));
    }
}

/// <summary>The users of the caller's own agency. Fails closed when the principal has no agency.</summary>
public sealed class AgencyUserScope : IAccessScopeStrategy<User>
{
    public string Name => nameof(AgencyUserScope);

    public Expression<Func<User, bool>> Scope(Principal principal, PermissionSet permissions)
    {
        if (!ScopeGuard.IsStaffInTenant(principal) || string.IsNullOrWhiteSpace(principal.AgencyId))
        {
            return ScopeGuard.None<User>();
        }

        var tenantId = principal.TenantId;
        var agencyId = principal.AgencyId;
        return u => u.TenantId == tenantId && u.AgencyId == agencyId;
    }
}

/// <summary>The users of the caller's own corporate account. Fails closed when the principal has no corporate account.</summary>
public sealed class CorporateUserScope : IAccessScopeStrategy<User>
{
    public string Name => nameof(CorporateUserScope);

    public Expression<Func<User, bool>> Scope(Principal principal, PermissionSet permissions)
    {
        if (!ScopeGuard.IsStaffInTenant(principal) || string.IsNullOrWhiteSpace(principal.CorporateId))
        {
            return ScopeGuard.None<User>();
        }

        var tenantId = principal.TenantId;
        var corporateId = principal.CorporateId;
        return u => u.TenantId == tenantId && u.CorporateId == corporateId;
    }
}

/// <summary>Only the caller's own user record. Used by families and kinds that manage nobody.</summary>
public sealed class SelfUserScope : IAccessScopeStrategy<User>
{
    public string Name => nameof(SelfUserScope);

    public Expression<Func<User, bool>> Scope(Principal principal, PermissionSet permissions)
    {
        if (principal.IsAnonymous || string.IsNullOrWhiteSpace(principal.TenantId) || string.IsNullOrWhiteSpace(principal.UserId))
        {
            return ScopeGuard.None<User>();
        }

        var tenantId = principal.TenantId;
        var userId = principal.UserId;
        return u => u.TenantId == tenantId && u.Id == userId;
    }
}
