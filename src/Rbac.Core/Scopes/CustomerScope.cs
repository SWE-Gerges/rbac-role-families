using System.Linq.Expressions;
using Rbac.Abstractions;
using Rbac.Core.Bookings;

namespace Rbac.Core.Scopes;

/// <summary>A customer sees only the bookings they own.</summary>
public sealed class CustomerScope : IAccessScopeStrategy<Booking>
{
    public string Name => nameof(CustomerScope);

    public Expression<Func<Booking, bool>> Scope(Principal principal, PermissionSet permissions)
    {
        if (principal.Kind != PrincipalKind.Customer
            || string.IsNullOrWhiteSpace(principal.TenantId)
            || string.IsNullOrWhiteSpace(principal.UserId))
        {
            return ScopeGuard.None<Booking>();
        }

        var tenantId = principal.TenantId;
        var userId = principal.UserId;
        return b => b.TenantId == tenantId && b.OwnerUserId == userId;
    }
}
