using System.Linq.Expressions;
using Rbac.Abstractions;

namespace Rbac.Core.Scopes;

internal static class ScopeGuard
{
    public static Expression<Func<T, bool>> None<T>() => _ => false;

    public static bool IsStaffInTenant(Principal principal) =>
        principal.Kind == PrincipalKind.Staff
        && !string.IsNullOrWhiteSpace(principal.TenantId)
        && !string.IsNullOrWhiteSpace(principal.UserId);
}
