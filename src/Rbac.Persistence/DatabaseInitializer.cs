using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Rbac.Abstractions;
using Rbac.Core.Catalog;
using Rbac.Core.Registry;
using Rbac.Core.Validation;
using Rbac.Persistence.Seeding;

namespace Rbac.Persistence;

/// <summary>Prepares the database when the host starts: schema, stored role catalog and, optionally, the demo data.</summary>
internal sealed class DatabaseInitializer(
    IServiceScopeFactory scopeFactory,
    IOptions<PersistenceOptions> options,
    ILogger<DatabaseInitializer> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;
        if (!settings.InitializeOnStartup)
        {
            return;
        }

        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<RbacDbContext>();
        var seed = scope.ServiceProvider.GetRequiredService<RoleCatalogSeed>();

        if (settings.Provider == DatabaseProvider.Postgres)
        {
            await DatabaseBootstrap.MigrateAsync(db, cancellationToken);
        }
        else
        {
            await SqliteSchema.CreateAsync(db, cancellationToken);
        }

        var seeded = await PermissionSeeder.SeedAsync(db, seed.Catalog, cancellationToken);
        if (seeded.Changed)
        {
            logger.LogInformation(
                "Permission catalog updated: {PermissionsAdded} permissions added, {PermissionsUpdated} updated, {RolesAdded} roles added, {RolesUpdated} roles updated, {DefaultsAdded} role defaults added",
                seeded.PermissionsAdded,
                seeded.PermissionsUpdated,
                seeded.RolesAdded,
                seeded.RolesUpdated,
                seeded.DefaultsAdded);
        }

        // From here on the stored catalog is the one that runs, so it is the one that must be valid.
        var holder = scope.ServiceProvider.GetRequiredService<RoleCatalogHolder>();
        holder.Replace(await RoleCatalogStore.LoadStructureAsync(db, cancellationToken));
        var problems = RbacConfigurationValidator.Validate(
            scope.ServiceProvider.GetRequiredService<IRoleCatalog>(),
            scope.ServiceProvider.GetServices<IStrategyRegistry>());
        if (problems.Count > 0)
        {
            foreach (var problem in problems)
            {
                logger.LogCritical("RBAC configuration problem in the stored role catalog: {Problem}", problem);
            }

            throw new RbacConfigurationException(problems);
        }

        if (settings.SeedDemoData)
        {
            await DemoSeeder.SeedAsync(db, seed.Catalog, cancellationToken);
        }

        logger.LogInformation("Database ready ({Provider}, demo data: {SeedDemoData})", settings.Provider, settings.SeedDemoData);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
