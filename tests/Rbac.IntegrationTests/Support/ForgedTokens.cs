using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Rbac.AspNetCore.Claims;

namespace Rbac.IntegrationTests.Support;

/// <summary>Signs tokens with the test key so tests can send claim sets the dev issuer would never produce.</summary>
public static class ForgedTokens
{
    public static string Create(
        IEnumerable<Claim> claims,
        string signingKey = ApiFactory.SigningKey,
        string issuer = ApiFactory.Issuer,
        string audience = ApiFactory.Audience,
        DateTime? notBefore = null,
        DateTime? expires = null,
        string algorithm = SecurityAlgorithms.HmacSha256)
    {
        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Subject = new ClaimsIdentity(claims),
            NotBefore = notBefore ?? now.AddMinutes(-1),
            Expires = expires ?? now.AddMinutes(30),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)), algorithm),
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    public static string Staff(
        string userId,
        string tenantId,
        string? role,
        string? agencyId = null,
        string? corporateId = null,
        int version = 1,
        string? kind = null)
    {
        var claims = new List<Claim>
        {
            new(RbacClaimTypes.Subject, userId),
            new(RbacClaimTypes.TenantId, tenantId),
            new(RbacClaimTypes.TokenVersion, version.ToString(System.Globalization.CultureInfo.InvariantCulture), ClaimValueTypes.Integer32),
        };
        if (role is not null)
        {
            claims.Add(new Claim(RbacClaimTypes.Role, role));
        }

        if (agencyId is not null)
        {
            claims.Add(new Claim(RbacClaimTypes.AgencyId, agencyId));
        }

        if (corporateId is not null)
        {
            claims.Add(new Claim(RbacClaimTypes.CorporateId, corporateId));
        }

        if (kind is not null)
        {
            claims.Add(new Claim(RbacClaimTypes.PrincipalKind, kind));
        }

        return Create(claims);
    }
}
