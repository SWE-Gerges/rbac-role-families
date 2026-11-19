using System.Linq.Expressions;
using Rbac.Abstractions;
using Rbac.Core.Bookings;

namespace Rbac.Core.Scopes;

/// <summary>
/// Bookings written by internal staff, plus guest bookings, within the tenant.
/// Anything owned by an agency or a corporate account is out of scope.
/// </summary>
public sealed class InternalScope : IAccessScopeStrategy<Booking>
{
    public string Name => nameof(InternalScope);

    public Expression<Func<Booking, bool>> Scope(Principal principal, PermissionSet permissions)
    {
        if (!ScopeGuard.IsStaffInTenant(principal))
        {
            return ScopeGuard.None<Booking>();
        }

        var tenantId = principal.TenantId;
        return b => b.TenantId == tenantId
            && b.AgencyId == null
            && b.CorporateId == null
            && (b.IsGuestBooking || b.OwnerRoleFamilyAtCreation == RoleFamily.Internal);
    }
}
