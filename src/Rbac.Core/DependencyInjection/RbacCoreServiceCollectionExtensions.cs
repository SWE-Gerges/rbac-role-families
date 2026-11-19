using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;
using Rbac.Core.Management;
using Rbac.Core.Registry;
using Rbac.Core.Scopes;
using Rbac.Core.Tokens;
using Rbac.Core.Users;
using Rbac.Core.Validation;

namespace Rbac.Core.DependencyInjection;

public static class RbacCoreServiceCollectionExtensions
{
    /// <summary>
    /// Registers the code-defined role catalog (the seed), the runtime catalog holder, the ownership stamper, the
    /// token version store and the startup validator. Call it before anything else that registers hosted services so
    /// that misconfiguration fails first.
    /// </summary>
    public static IServiceCollection AddRbacCore(this IServiceCollection services, RoleCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(catalog);

        services.AddSingleton(new RoleCatalogSeed(catalog));
        services.AddSingleton(new RoleCatalogHolder(catalog));
        services.AddSingleton<IRoleCatalog>(provider => provider.GetRequiredService<RoleCatalogHolder>());
        services.AddHostedService<RbacStartupValidator>();
        services.TryAddSingleton<ITokenVersionStore, InMemoryTokenVersionStore>();
        services.TryAddSingleton<OwnershipStamper>();
        return services;
    }

    /// <summary>Registers an explicit family-to-strategy registry and the resolver for a resource type.</summary>
    public static IServiceCollection AddScopeStrategies<TResource>(
        this IServiceCollection services,
        Action<StrategyRegistryBuilder<TResource>> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        return services.AddScopeStrategies<TResource>((_, builder) => configure(builder));
    }

    /// <summary>The same, for strategies that need services (for example the role catalog) to be constructed.</summary>
    public static IServiceCollection AddScopeStrategies<TResource>(
        this IServiceCollection services,
        Action<IServiceProvider, StrategyRegistryBuilder<TResource>> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddSingleton(provider =>
        {
            var builder = StrategyRegistry<TResource>.Create();
            configure(provider, builder);
            return builder.Build();
        });
        services.AddSingleton<IStrategyRegistry>(provider => provider.GetRequiredService<StrategyRegistry<TResource>>());
        services.AddSingleton<IScopeResolver<TResource>, ScopeResolver<TResource>>();
        return services;
    }

    /// <summary>The booking strategies: one per family, plus customers. Anything else falls back to no access.</summary>
    public static IServiceCollection AddBookingScopes(this IServiceCollection services) =>
        services.AddScopeStrategies<Booking>(registry => registry
            .ForFamily(RoleFamily.System, new SystemScope())
            .ForFamily(RoleFamily.Finance, new FinanceScope())
            .ForFamily(RoleFamily.Internal, new InternalScope())
            .ForFamily(RoleFamily.Corporate, new CorporateScope())
            .ForFamily(RoleFamily.Agency, new AgencyScope())
            .ForFamily(RoleFamily.Viewer, new ViewerScope())
            .ForCustomers(new CustomerScope()));

    /// <summary>User visibility: one strategy per family, so user lists and by-id lookups obey a single predicate.</summary>
    public static IServiceCollection AddUserScopes(this IServiceCollection services) =>
        services.AddScopeStrategies<User>((provider, registry) => registry
            .ForFamily(RoleFamily.System, new SystemUserScope())
            .ForFamily(RoleFamily.Finance, new SelfUserScope())
            .ForFamily(RoleFamily.Internal, new InternalUserScope(provider.GetRequiredService<IRoleCatalog>()))
            .ForFamily(RoleFamily.Corporate, new CorporateUserScope())
            .ForFamily(RoleFamily.Agency, new AgencyUserScope())
            .ForFamily(RoleFamily.Viewer, new SelfUserScope())
            .ForCustomers(new SelfUserScope()));

    /// <summary>The creation graph: one management strategy per family, validated at startup.</summary>
    public static IServiceCollection AddRoleManagement(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        var registry = RoleManagementRegistry.Create()
            .ForFamily(RoleFamily.System, new CrossAccountRoleManagement())
            .ForFamily(RoleFamily.Finance, new DenyAllRoleManagement())
            .ForFamily(RoleFamily.Internal, new CrossAccountRoleManagement())
            .ForFamily(RoleFamily.Corporate, new AccountRoleManagement())
            .ForFamily(RoleFamily.Agency, new AccountRoleManagement())
            .ForFamily(RoleFamily.Viewer, new DenyAllRoleManagement())
            .Build();

        services.AddSingleton(registry);
        services.AddSingleton<IStrategyRegistry>(registry);
        services.AddSingleton<RoleManagementResolver>();
        return services;
    }
}
