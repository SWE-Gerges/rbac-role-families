using System.Linq.Expressions;
using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;

namespace Rbac.Core.Scopes;

/// <summary>
/// The caller's own agency. An agency admin sees the whole agency; agency staff see only their own
/// bookings unless they hold <see cref="Permissions.BookingsViewAllAgency"/>.
/// Fails closed when the principal is not bound to an agency.
/// </summary>
public sealed class AgencyScope : IAccessScopeStrategy<Booking>
{
    public string Name => nameof(AgencyScope);

    public Expression<Func<Booking, bool>> Scope(Principal principal, PermissionSet permissions)
    {
        if (!ScopeGuard.IsStaffInTenant(principal) || string.IsNullOrWhiteSpace(principal.AgencyId))
        {
            return ScopeGuard.None<Booking>();
        }

        var tenantId = principal.TenantId;
        var agencyId = principal.AgencyId;
        var userId = principal.UserId;

        if (principal.RoleKey == RoleKeys.AgencyAdmin || permissions.Has(Permissions.BookingsViewAllAgency))
        {
            return b => b.TenantId == tenantId && b.AgencyId == agencyId;
        }

        return b => b.TenantId == tenantId && b.AgencyId == agencyId && b.OwnerUserId == userId;
    }
}
