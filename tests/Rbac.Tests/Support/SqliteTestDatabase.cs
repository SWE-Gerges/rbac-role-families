using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;
using Rbac.Core.DependencyInjection;
using Rbac.Core.Users;
using Rbac.Persistence;
using Rbac.Persistence.Seeding;

namespace Rbac.Tests.Support;

/// <summary>A private in-memory SQLite database with the schema, role catalog and demo data. Contexts share one open connection.</summary>
internal sealed class SqliteTestDatabase : IAsyncDisposable
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    private SqliteTestDatabase()
    {
    }

    /// <summary>Every EF warning-level (or worse) message logged by contexts created here.</summary>
    public List<string> Warnings { get; } = [];

    public static async Task<SqliteTestDatabase> CreateAsync(bool seed = true, bool seedCatalog = true)
    {
        var database = new SqliteTestDatabase();
        await database._connection.OpenAsync();

        await using var context = database.CreateContext(tenantId: null);
        await SqliteSchema.CreateAsync(context, CancellationToken.None);
        var catalog = DefaultRoleCatalog.Create();
        if (seedCatalog)
        {
            await PermissionSeeder.SeedAsync(context, catalog, CancellationToken.None);
        }

        if (seed)
        {
            await DemoSeeder.SeedAsync(context, catalog, CancellationToken.None);
        }

        database.Warnings.Clear();
        return database;
    }

    public RbacDbContext CreateContext(string? tenantId)
    {
        var options = new DbContextOptionsBuilder<RbacDbContext>()
            .UseSqlite(_connection)
            .LogTo(Warnings.Add, LogLevel.Warning)
            .Options;
        return new RbacDbContext(options, new FixedTenantContext(tenantId));
    }

    public async ValueTask DisposeAsync() => await _connection.DisposeAsync();
}

internal static class TestServices
{
    /// <summary>The resolver exactly as <c>AddRbacCore</c> and <c>AddBookingScopes</c> register it.</summary>
    public static ResolverFixture Resolver()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddRbacCore(DefaultRoleCatalog.Create());
        services.AddBookingScopes();
        services.AddUserScopes();
        var provider = services.BuildServiceProvider();
        return new ResolverFixture(
            provider.GetRequiredService<IScopeResolver<Booking>>(),
            provider.GetRequiredService<IRoleCatalog>(),
            provider.GetRequiredService<IScopeResolver<User>>());
    }
}

internal sealed record ResolverFixture(IScopeResolver<Booking> Resolver, IRoleCatalog Catalog, IScopeResolver<User> Users);

internal static class SeedPrincipals
{
    public static Principal From(SeedUser user, int tokenVersion = 1) =>
        user.Kind == PrincipalKind.Customer
            ? Principal.ForCustomer(user.Id, user.TenantId, tokenVersion)
            : Principal.ForStaff(user.Id, user.TenantId, user.RoleKey!, user.AgencyId, user.CorporateId, tokenVersion);

    public static SeedUser User(string id) => DemoSeedData.Users.Single(u => u.Id == id);
}

/// <summary>A WAL-mode SQLite file that many connections can write to at once. It is removed, with its WAL files, on dispose.</summary>
internal sealed class SqliteFileDatabase : IDisposable
{
    private readonly string _path = Path.Combine(AppContext.BaseDirectory, $"rbac-test-{Guid.NewGuid():N}.db");

    public SqliteFileDatabase()
    {
        ConnectionString = $"Data Source={_path};Pooling=False";
        using var connection = new SqliteConnection(ConnectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL;";
        command.ExecuteNonQuery();
    }

    public string ConnectionString { get; }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var file in new[] { _path, _path + "-wal", _path + "-shm" })
        {
            File.Delete(file);
        }
    }
}
