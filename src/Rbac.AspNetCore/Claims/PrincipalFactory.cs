using System.Globalization;
using System.Security.Claims;
using Rbac.Abstractions;

namespace Rbac.AspNetCore.Claims;

/// <summary>
/// Builds a <see cref="Principal"/> from validated claims. Anything that is missing, malformed or unknown
/// becomes <see cref="Principal.Anonymous"/>: there is no default role, and customers are never inferred.
/// </summary>
public sealed class PrincipalFactory(IRoleCatalog catalog)
{
    public Principal Create(ClaimsPrincipal? user)
    {
        if (user?.Identity?.IsAuthenticated != true)
        {
            return Principal.Anonymous;
        }

        var userId = Value(user, RbacClaimTypes.Subject);
        var tenantId = Value(user, RbacClaimTypes.TenantId);
        if (userId is null || tenantId is null)
        {
            return Principal.Anonymous;
        }

        var version = int.TryParse(Value(user, RbacClaimTypes.TokenVersion), NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : 0;

        switch (Value(user, RbacClaimTypes.PrincipalKind) ?? RbacClaimTypes.StaffKind)
        {
            case RbacClaimTypes.CustomerKind:
                return Principal.ForCustomer(userId, tenantId, version);

            case RbacClaimTypes.StaffKind:
                var roleKey = Value(user, RbacClaimTypes.Role);
                return catalog.Find(roleKey) is null
                    ? Principal.Anonymous
                    : Principal.ForStaff(
                        userId,
                        tenantId,
                        roleKey!,
                        Value(user, RbacClaimTypes.AgencyId),
                        Value(user, RbacClaimTypes.CorporateId),
                        version);

            default:
                return Principal.Anonymous;
        }
    }

    private static string? Value(ClaimsPrincipal user, string type)
    {
        var value = user.FindFirst(type)?.Value;
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
}
