using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Rbac.Abstractions;

namespace Rbac.AspNetCore.Authorization;

/// <summary>Requires the caller to hold a permission, resolved live for the current request.</summary>
public sealed class PermissionRequirement(string permission) : IAuthorizationRequirement
{
    public string Permission { get; } = permission ?? throw new ArgumentNullException(nameof(permission));
}

/// <summary>
/// Gates an endpoint on a permission: <c>[RequirePermission("bookings.cancel")]</c>.
/// The policy is created on demand by <see cref="PermissionPolicyProvider"/>.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class RequirePermissionAttribute(string permission) : AuthorizeAttribute(PermissionPolicy.NameFor(permission))
{
    public string Permission { get; } = permission;
}

public static class PermissionPolicy
{
    private const string Prefix = "permission:";

    public static string NameFor(string permission)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);
        return Prefix + permission;
    }

    public static bool TryGetPermission(string policyName, out string permission)
    {
        if (policyName.StartsWith(Prefix, StringComparison.Ordinal) && policyName.Length > Prefix.Length)
        {
            permission = policyName[Prefix.Length..];
            return true;
        }

        permission = string.Empty;
        return false;
    }
}

/// <summary>Builds <c>permission:*</c> policies on demand and leaves every other policy name to the default provider.</summary>
public sealed class PermissionPolicyProvider(IOptions<AuthorizationOptions> options) : IAuthorizationPolicyProvider
{
    private readonly DefaultAuthorizationPolicyProvider _default = new(options);
    private readonly ConcurrentDictionary<string, AuthorizationPolicy> _policies = new(StringComparer.Ordinal);

    public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => _default.GetDefaultPolicyAsync();

    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => _default.GetFallbackPolicyAsync();

    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (!PermissionPolicy.TryGetPermission(policyName, out var permission))
        {
            return _default.GetPolicyAsync(policyName);
        }

        var policy = _policies.GetOrAdd(policyName, _ => new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(new PermissionRequirement(permission))
            .Build());
        return Task.FromResult<AuthorizationPolicy?>(policy);
    }
}

/// <summary>
/// Succeeds only when the live permissions of the request's principal contain the required permission.
/// It never fails explicitly, so a missing permission is a plain 403 for an authenticated caller.
/// </summary>
public sealed class PermissionAuthorizationHandler(ICurrentPermissions permissions)
    : AuthorizationHandler<PermissionRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        var cancellationToken = (context.Resource as HttpContext)?.RequestAborted ?? CancellationToken.None;
        var granted = await permissions.GetAsync(cancellationToken);
        if (granted.Has(requirement.Permission))
        {
            context.Succeed(requirement);
        }
    }
}
