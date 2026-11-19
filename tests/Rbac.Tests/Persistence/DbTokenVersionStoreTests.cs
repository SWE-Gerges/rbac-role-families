using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Rbac.Abstractions;
using Rbac.Persistence;
using Rbac.Tests.Support;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Persistence;

public class DbTokenVersionStoreTests
{
    private static async Task<(ServiceProvider Provider, SqliteConnection Connection)> CreateAsync()
    {
        var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();
        var services = new ServiceCollection();
        services.AddScoped<ITenantContext>(_ => FixedTenantContext.None);
        services.AddDbContext<RbacDbContext>(options => options.UseSqlite(connection));
        services.AddSingleton<ITokenVersionStore, DbTokenVersionStore>();
        var provider = services.BuildServiceProvider();
        await using (var scope = provider.CreateAsyncScope())
        {
            await SqliteSchema.CreateAsync(scope.ServiceProvider.GetRequiredService<RbacDbContext>(), CancellationToken.None);
        }

        return (provider, connection);
    }

    [Fact]
    public async Task A_user_that_was_never_bumped_is_on_version_one_and_the_first_bump_writes_two()
    {
        var (provider, connection) = await CreateAsync();
        await using var _ = provider;
        await using var __ = connection;
        var store = provider.GetRequiredService<ITokenVersionStore>();

        (await store.GetCurrentVersionAsync("t1", "u1", CancellationToken.None)).ShouldBe(1);
        (await store.BumpAsync("t1", "u1", CancellationToken.None)).ShouldBe(2);
        (await store.BumpAsync("t1", "u1", CancellationToken.None)).ShouldBe(3);
        (await store.GetCurrentVersionAsync("t1", "u1", CancellationToken.None)).ShouldBe(3);
    }

    [Fact]
    public async Task Bumps_are_isolated_per_user_and_per_tenant()
    {
        var (provider, connection) = await CreateAsync();
        await using var _ = provider;
        await using var __ = connection;
        var store = provider.GetRequiredService<ITokenVersionStore>();

        await store.BumpAsync("t1", "u1", CancellationToken.None);

        (await store.GetCurrentVersionAsync("t1", "u2", CancellationToken.None)).ShouldBe(1);
        (await store.GetCurrentVersionAsync("t2", "u1", CancellationToken.None)).ShouldBe(1);
    }

    [Fact]
    public async Task A_new_store_instance_over_the_same_database_remembers_earlier_bumps()
    {
        var (provider, connection) = await CreateAsync();
        await using var _ = provider;
        await using var __ = connection;
        await provider.GetRequiredService<ITokenVersionStore>().BumpAsync("t1", "u1", CancellationToken.None);

        // A restart builds a new store over the same database.
        var restarted = new DbTokenVersionStore(provider.GetRequiredService<IServiceScopeFactory>());

        (await restarted.GetCurrentVersionAsync("t1", "u1", CancellationToken.None)).ShouldBe(2);
    }

    [Fact]
    public async Task A_bump_inside_a_rolled_back_transaction_is_not_kept()
    {
        var (provider, connection) = await CreateAsync();
        await using var _ = provider;
        await using var __ = connection;
        await using (var scope = provider.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RbacDbContext>();
            await using var transaction = await db.Database.BeginTransactionAsync();
            await DbTokenVersionStore.BumpAsync(db, "t1", "u1", CancellationToken.None);
            await transaction.RollbackAsync();
        }

        (await provider.GetRequiredService<ITokenVersionStore>().GetCurrentVersionAsync("t1", "u1", CancellationToken.None)).ShouldBe(1);
    }

    [Fact]
    public async Task Concurrent_bumps_from_separate_connections_are_atomic_and_never_lost()
    {
        using var file = new SqliteFileDatabase();
        var services = new ServiceCollection();
        services.AddScoped<ITenantContext>(_ => FixedTenantContext.None);
        services.AddDbContext<RbacDbContext>(options => options.UseSqlite(file.ConnectionString));
        services.AddSingleton<ITokenVersionStore, DbTokenVersionStore>();
        await using var provider = services.BuildServiceProvider();
        await using (var scope = provider.CreateAsyncScope())
        {
            await SqliteSchema.CreateAsync(scope.ServiceProvider.GetRequiredService<RbacDbContext>(), CancellationToken.None);
        }

        var store = provider.GetRequiredService<ITokenVersionStore>();

        await Task.WhenAll(Enumerable.Range(0, 100).Select(_ => Task.Run(
            async () => await store.BumpAsync("t1", "u1", CancellationToken.None),
            TestContext.Current.CancellationToken)));

        (await store.GetCurrentVersionAsync("t1", "u1", CancellationToken.None)).ShouldBe(101);
    }
}
