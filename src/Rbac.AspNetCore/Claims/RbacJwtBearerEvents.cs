using System.Globalization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Rbac.Abstractions;

namespace Rbac.AspNetCore.Claims;

/// <summary>
/// Rejects a token whose version is not the user's current version, so a role or permission edit that bumps
/// the version revokes every session issued before it. A rejected token is a 401, not a 403.
/// </summary>
public sealed class RbacJwtBearerEvents : JwtBearerEvents
{
    public override async Task TokenValidated(TokenValidatedContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var user = context.Principal;
        var userId = user?.FindFirst(RbacClaimTypes.Subject)?.Value;
        var tenantId = user?.FindFirst(RbacClaimTypes.TenantId)?.Value;
        var versionClaim = user?.FindFirst(RbacClaimTypes.TokenVersion)?.Value;

        if (string.IsNullOrWhiteSpace(userId)
            || string.IsNullOrWhiteSpace(tenantId)
            || !int.TryParse(versionClaim, NumberStyles.None, CultureInfo.InvariantCulture, out var tokenVersion))
        {
            context.Fail("The token does not identify a user, a tenant and a token version.");
            return;
        }

        var store = context.HttpContext.RequestServices.GetRequiredService<ITokenVersionStore>();
        var current = await store.GetCurrentVersionAsync(tenantId, userId, context.HttpContext.RequestAborted);
        if (tokenVersion != current)
        {
            context.Fail("The token has been revoked.");
        }
    }
}
