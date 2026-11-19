using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Rbac.Abstractions;
using Rbac.AspNetCore.Authorization;
using Rbac.AspNetCore.Claims;
using Rbac.AspNetCore.Http;

namespace Rbac.AspNetCore;

public static class RbacAspNetCoreServiceCollectionExtensions
{
    /// <summary>
    /// Registers claims-to-principal mapping, the request principal and tenant, the permission authorization
    /// handler and policy provider, a deny-by-default fallback policy, ProblemDetails and the exception handler.
    /// Authentication itself (for example JWT bearer with <see cref="RbacJwtBearerEvents"/>) is configured by the host.
    /// </summary>
    public static IServiceCollection AddRbacAspNetCore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddHttpContextAccessor();
        services.TryAddSingleton<PrincipalFactory>();
        services.TryAddScoped<IPrincipalContext, HttpPrincipalContext>();
        services.TryAddScoped<ICurrentPermissions, CurrentPermissions>();
        services.Replace(ServiceDescriptor.Scoped<ICorrelationContext, HttpCorrelationContext>());
        services.Replace(ServiceDescriptor.Scoped<ITenantContext, PrincipalTenantContext>());

        services.AddAuthorization(options =>
        {
            // Every endpoint requires an authenticated caller unless it opts out with [AllowAnonymous].
            options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
        });
        services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();
        services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();

        services.AddProblemDetails(options =>
        {
            options.CustomizeProblemDetails = context =>
            {
                var correlationId = context.HttpContext.GetCorrelationId();
                if (correlationId is not null)
                {
                    context.ProblemDetails.Extensions["correlationId"] = correlationId;
                }
            };
        });
        services.AddExceptionHandler<GlobalExceptionHandler>();
        return services;
    }
}
