using Microsoft.EntityFrameworkCore;
using Rbac.Persistence.Seeding;
using Rbac.Tests.Support;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Persistence;

public class TenantFilterTests
{
    [Fact]
    public async Task A_context_for_tenant_b_never_returns_tenant_a_bookings_users_or_overrides()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(SeedIds.TenantB);

        var bookings = await db.Bookings.ToListAsync(TestContext.Current.CancellationToken);
        var users = await db.Users.ToListAsync(TestContext.Current.CancellationToken);
        var overrides = await db.UserPermissions.ToListAsync(TestContext.Current.CancellationToken);

        bookings.ShouldNotBeEmpty();
        bookings.ShouldAllBe(b => b.TenantId == SeedIds.TenantB);
        users.ShouldAllBe(u => u.TenantId == SeedIds.TenantB);
        overrides.ShouldBeEmpty("tenant b has no per-user overrides, and tenant a's must not leak");
    }

    [Fact]
    public async Task A_by_id_lookup_of_another_tenants_booking_finds_nothing()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(SeedIds.TenantB);

        var found = await db.Bookings.SingleOrDefaultAsync(b => b.Id == "bk-a-001", TestContext.Current.CancellationToken);

        found.ShouldBeNull();
    }

    [Fact]
    public async Task Without_a_tenant_the_filter_matches_nothing()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(tenantId: null);

        (await db.Bookings.CountAsync(TestContext.Current.CancellationToken)).ShouldBe(0);
        (await db.Users.CountAsync(TestContext.Current.CancellationToken)).ShouldBe(0);
    }

    [Fact]
    public async Task An_unknown_tenant_matches_nothing()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext("tenant-that-does-not-exist");

        (await db.Bookings.CountAsync(TestContext.Current.CancellationToken)).ShouldBe(0);
    }

    [Fact]
    public async Task The_seed_has_two_tenants_and_sixty_bookings_visible_only_when_filters_are_ignored()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(SeedIds.TenantA);

        (await db.Bookings.IgnoreQueryFilters().CountAsync(TestContext.Current.CancellationToken)).ShouldBe(60);
        (await db.Bookings.CountAsync(TestContext.Current.CancellationToken)).ShouldBe(48);
        (await db.Tenants.CountAsync(TestContext.Current.CancellationToken)).ShouldBe(2);
    }

    [Fact]
    public async Task The_filter_follows_the_tenant_of_each_context_instance()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();

        await using var a = database.CreateContext(SeedIds.TenantA);
        await using var b = database.CreateContext(SeedIds.TenantB);

        (await a.Bookings.CountAsync(TestContext.Current.CancellationToken)).ShouldBe(48);
        (await b.Bookings.CountAsync(TestContext.Current.CancellationToken)).ShouldBe(12);
    }

    [Fact]
    public void The_seed_is_deterministic()
    {
        var catalog = Rbac.Core.Catalog.DefaultRoleCatalog.Create();

        var first = DemoSeedData.CreateBookings(catalog);
        var second = DemoSeedData.CreateBookings(catalog);

        first.Select(b => (b.Id, b.OwnerUserId, b.Status, b.Amount, b.CreatedAt))
            .ShouldBe(second.Select(b => (b.Id, b.OwnerUserId, b.Status, b.Amount, b.CreatedAt)));
        first.Select(b => b.Status).Distinct().Count().ShouldBe(6, "every status is represented");
        first.Select(b => b.Id).Distinct().Count().ShouldBe(60);
    }
}
