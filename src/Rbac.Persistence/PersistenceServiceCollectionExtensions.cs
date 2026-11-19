using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Registry;
using Rbac.Core.Users;
using Rbac.Persistence.Administration;
using Rbac.Persistence.Caching;

namespace Rbac.Persistence;

public static class PersistenceServiceCollectionExtensions
{
    /// <summary>
    /// Registers the DbContext (SQLite or Npgsql), the live permission store, the scoped booking query and the
    /// startup initializer. Requires <c>AddRbacCore</c> and <c>AddBookingScopes</c>; the host binds <see cref="PersistenceOptions"/>.
    /// </summary>
    public static IServiceCollection AddRbacPersistence(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<PersistenceOptions>()
            .Validate(o => Enum.IsDefined(o.Provider), "Persistence:Provider must be Sqlite or Postgres.")
            .Validate(o => !string.IsNullOrWhiteSpace(o.ConnectionString), "Persistence:ConnectionString is required.")
            .ValidateOnStart();

        // Fail closed: without a request principal the tenant filter matches nothing.
        services.TryAddScoped<ITenantContext>(_ => FixedTenantContext.None);

        services.AddDbContext<RbacDbContext>((provider, builder) =>
        {
            var settings = provider.GetRequiredService<IOptions<PersistenceOptions>>().Value;
            switch (settings.Provider)
            {
                case DatabaseProvider.Postgres:
                    builder.UseNpgsql(settings.ConnectionString);
                    break;
                default:
                    builder.UseSqlite(settings.ConnectionString);
                    break;
            }
        });

        services.Replace(ServiceDescriptor.Singleton<ITokenVersionStore, DbTokenVersionStore>());
        services.AddSingleton<PermissionCache>();
        services.AddSingleton<PermissionCacheStatistics>();
        services.AddScoped<DbPermissionStore>();
        services.AddScoped<IPermissionStore>(provider =>
        {
            var database = provider.GetRequiredService<DbPermissionStore>();
            return provider.GetRequiredService<IOptions<PersistenceOptions>>().Value.CachePermissions
                ? new CachingPermissionStore(
                    database,
                    provider.GetRequiredService<RbacDbContext>(),
                    provider.GetRequiredService<PermissionCache>(),
                    provider.GetRequiredService<PermissionCacheStatistics>())
                : database;
        });
        services.AddScoped<IScopedQuery<Booking>>(provider => new ScopedQuery<Booking>(
            provider.GetRequiredService<RbacDbContext>().Bookings,
            provider.GetRequiredService<IScopeResolver<Booking>>()));
        services.AddScoped<IScopedQuery<User>>(provider => new ScopedQuery<User>(
            provider.GetRequiredService<RbacDbContext>().Users,
            provider.GetRequiredService<IScopeResolver<User>>()));
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<ICorrelationContext, NoCorrelationContext>();
        services.AddScoped<IAuditLog, AuditLog>();
        services.AddScoped<ManagementSupport>();
        services.AddScoped<IEffectivePrincipalResolver, OnBehalfResolver>();
        services.AddScoped<UserAdministration>();
        services.AddScoped<PermissionAdministration>();
        services.AddHostedService<DatabaseInitializer>();
        return services;
    }
}
