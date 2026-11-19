using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Rbac.Demo;

internal sealed record IssuedToken(string AccessToken, DateTimeOffset ExpiresAt);

/// <summary>Signs HS256 tokens for the demo. The same key validates them, so this is not an identity provider.</summary>
internal sealed class DevTokenIssuer(IOptions<DemoOptions> options, TimeProvider timeProvider)
{
    private readonly JsonWebTokenHandler _handler = new();

    public IssuedToken Issue(IEnumerable<Claim> claims)
    {
        var jwt = options.Value.Jwt;
        var now = timeProvider.GetUtcNow();
        var expires = now.AddMinutes(jwt.TokenLifetimeMinutes);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = jwt.Issuer,
            Audience = jwt.Audience,
            Subject = new ClaimsIdentity(claims),
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SigningKey)),
                SecurityAlgorithms.HmacSha256),
        };

        return new IssuedToken(_handler.CreateToken(descriptor), expires);
    }
}
