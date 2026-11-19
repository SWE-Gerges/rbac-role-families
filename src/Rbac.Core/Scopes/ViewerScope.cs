using System.Linq.Expressions;
using Rbac.Abstractions;
using Rbac.Core.Bookings;

namespace Rbac.Core.Scopes;

/// <summary>Viewers read reports, never booking rows.</summary>
public sealed class ViewerScope : IAccessScopeStrategy<Booking>
{
    public string Name => nameof(ViewerScope);

    public Expression<Func<Booking, bool>> Scope(Principal principal, PermissionSet permissions) =>
        ScopeGuard.None<Booking>();
}
