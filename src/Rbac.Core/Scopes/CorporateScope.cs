using System.Linq.Expressions;
using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;

namespace Rbac.Core.Scopes;

/// <summary>
/// The caller's own corporate account. A corporate admin sees the whole account; corporate staff see only
/// their own bookings unless they hold <see cref="Permissions.BookingsViewAllCorporate"/>.
/// Fails closed when the principal is not bound to a corporate account.
/// </summary>
public sealed class CorporateScope : IAccessScopeStrategy<Booking>
{
    public string Name => nameof(CorporateScope);

    public Expression<Func<Booking, bool>> Scope(Principal principal, PermissionSet permissions)
    {
        if (!ScopeGuard.IsStaffInTenant(principal) || string.IsNullOrWhiteSpace(principal.CorporateId))
        {
            return ScopeGuard.None<Booking>();
        }

        var tenantId = principal.TenantId;
        var corporateId = principal.CorporateId;
        var userId = principal.UserId;

        if (principal.RoleKey == RoleKeys.CorporateAdmin || permissions.Has(Permissions.BookingsViewAllCorporate))
        {
            return b => b.TenantId == tenantId && b.CorporateId == corporateId;
        }

        return b => b.TenantId == tenantId && b.CorporateId == corporateId && b.OwnerUserId == userId;
    }
}
