using Microsoft.Extensions.Hosting;

namespace Rbac.Demo;

internal static class DataProtectionExtensions
{
    private const string WarmUpTypeName = "Microsoft.AspNetCore.DataProtection.Internal.DataProtectionHostedService";

    /// <summary>
    /// <c>AddAuthentication</c> registers ASP.NET Core data protection, whose hosted service creates a key ring at startup
    /// and logs two warnings when the keys land in an unprotected directory. This API validates signed JWTs and
    /// protects nothing, so the warm-up is removed instead of silencing the logger category. The key ring is still created
    /// lazily if something ever asks for it; a test asserts that startup logs no data protection warnings.
    /// </summary>
    public static IServiceCollection RemoveDataProtectionKeyRingWarmUp(this IServiceCollection services)
    {
        foreach (var descriptor in services
                     .Where(d => d.ServiceType == typeof(IHostedService) && d.ImplementationType?.FullName == WarmUpTypeName)
                     .ToList())
        {
            services.Remove(descriptor);
        }

        return services;
    }
}
