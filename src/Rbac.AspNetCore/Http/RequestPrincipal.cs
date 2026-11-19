using Microsoft.AspNetCore.Http;
using Rbac.Abstractions;
using Rbac.AspNetCore.Claims;

namespace Rbac.AspNetCore.Http;

/// <summary>
/// The principal of the current request: the effective principal when the caller acts on behalf of someone (set by
/// <see cref="OnBehalfMiddleware"/>), otherwise the one derived from the authenticated user claims.
/// </summary>
internal sealed class HttpPrincipalContext(IHttpContextAccessor accessor, PrincipalFactory factory) : IPrincipalContext
{
    public Principal Current =>
        accessor.HttpContext?.Items.TryGetValue(OnBehalfMiddleware.PrincipalItemKey, out var effective) == true && effective is Principal onBehalf
            ? onBehalf
            : factory.Create(accessor.HttpContext?.User);
}

/// <summary>Resolves the live permissions of the request's principal once and reuses them for the rest of the request.</summary>
internal sealed class CurrentPermissions(IPrincipalContext principalContext, IPermissionStore store) : ICurrentPermissions
{
    private Task<PermissionSet>? _permissions;

    public ValueTask<PermissionSet> GetAsync(CancellationToken cancellationToken)
    {
        _permissions ??= LoadAsync(principalContext.Current, cancellationToken);
        return new ValueTask<PermissionSet>(_permissions);
    }

    private async Task<PermissionSet> LoadAsync(Principal principal, CancellationToken cancellationToken) =>
        await store.GetEffectivePermissionsAsync(principal, cancellationToken);
}

/// <summary>The tenant of the request's principal. Anonymous callers have none, which matches no rows.</summary>
internal sealed class PrincipalTenantContext(IPrincipalContext principalContext) : ITenantContext
{
    public string? TenantId
    {
        get
        {
            var principal = principalContext.Current;
            return principal.IsAnonymous ? null : principal.TenantId;
        }
    }
}
