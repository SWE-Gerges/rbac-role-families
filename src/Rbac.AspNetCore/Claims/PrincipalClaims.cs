using System.Globalization;
using System.Security.Claims;
using Rbac.Abstractions;

namespace Rbac.AspNetCore.Claims;

/// <summary>The claims that represent a <see cref="Principal"/> in a token.</summary>
public static class PrincipalClaims
{
    public static IReadOnlyList<Claim> ToClaims(Principal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (principal.IsAnonymous)
        {
            return [];
        }

        var claims = new List<Claim>
        {
            new(RbacClaimTypes.Subject, principal.UserId),
            new(RbacClaimTypes.TenantId, principal.TenantId),
            new(RbacClaimTypes.PrincipalKind, principal.Kind == PrincipalKind.Customer ? RbacClaimTypes.CustomerKind : RbacClaimTypes.StaffKind),
            new(RbacClaimTypes.TokenVersion, principal.TokenVersion.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer32),
        };

        if (principal.Kind == PrincipalKind.Staff)
        {
            AddIfPresent(claims, RbacClaimTypes.Role, principal.RoleKey);
            AddIfPresent(claims, RbacClaimTypes.AgencyId, principal.AgencyId);
            AddIfPresent(claims, RbacClaimTypes.CorporateId, principal.CorporateId);
        }

        return claims;
    }

    private static void AddIfPresent(List<Claim> claims, string type, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            claims.Add(new Claim(type, value));
        }
    }
}
