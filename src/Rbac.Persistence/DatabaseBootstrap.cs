using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage;

namespace Rbac.Persistence;

public static class DatabaseBootstrap
{
    /// <summary>
    /// Applies the committed migrations. EF Core's first step in <c>Migrate</c> is an optimistic read of the history
    /// table, which on a fresh database fails by design and is logged as an error by the command logger. Creating the
    /// database and the (empty) history table first makes that read succeed, so a clean start logs no errors and a real
    /// failed command stays visible.
    /// </summary>
    public static async Task MigrateAsync(RbacDbContext db, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);

        var creator = db.GetService<IRelationalDatabaseCreator>();
        if (!await creator.ExistsAsync(cancellationToken))
        {
            await creator.CreateAsync(cancellationToken);
        }

        // Not ExistsAsync: that probes by selecting from the table, which is the very failure being avoided.
        var history = db.GetService<IHistoryRepository>();
        await db.Database.ExecuteSqlRawAsync(history.GetCreateIfNotExistsScript(), cancellationToken);

        await db.Database.MigrateAsync(cancellationToken);
    }
}
