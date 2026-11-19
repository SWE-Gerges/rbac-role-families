using System.Linq.Expressions;
using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;

namespace Rbac.Core.Scopes;

/// <summary>Only refund-related bookings, unless the caller holds <see cref="Permissions.ReportsView"/>.</summary>
public sealed class FinanceScope : IAccessScopeStrategy<Booking>
{
    public string Name => nameof(FinanceScope);

    public Expression<Func<Booking, bool>> Scope(Principal principal, PermissionSet permissions)
    {
        if (!ScopeGuard.IsStaffInTenant(principal))
        {
            return ScopeGuard.None<Booking>();
        }

        var tenantId = principal.TenantId;

        if (permissions.Has(Permissions.ReportsView))
        {
            return b => b.TenantId == tenantId;
        }

        return b => b.TenantId == tenantId
            && (b.Status == BookingStatus.RefundRequested || b.Status == BookingStatus.Refunded);
    }
}
