using System.Linq.Expressions;
using Rbac.Abstractions;
using Rbac.Core.Bookings;

namespace Rbac.Core.Scopes;

/// <summary>Every booking in the caller's tenant. The tenant is always constrained.</summary>
public sealed class SystemScope : IAccessScopeStrategy<Booking>
{
    public string Name => nameof(SystemScope);

    public Expression<Func<Booking, bool>> Scope(Principal principal, PermissionSet permissions)
    {
        if (!ScopeGuard.IsStaffInTenant(principal))
        {
            return ScopeGuard.None<Booking>();
        }

        var tenantId = principal.TenantId;
        return b => b.TenantId == tenantId;
    }
}
