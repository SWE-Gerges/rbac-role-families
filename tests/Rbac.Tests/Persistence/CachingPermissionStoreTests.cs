using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Rbac.Abstractions;
using Rbac.Core.Catalog;
using Rbac.Persistence;
using Rbac.Persistence.Caching;
using Rbac.Persistence.Seeding;
using Rbac.Tests.Support;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Persistence;

public class CachingPermissionStoreTests
{
    private static readonly Principal Staff = Principal.ForStaff(SeedIds.AgencyStaffA, SeedIds.TenantA, RoleKeys.AgencyStaff, SeedIds.AgencyA1);

    /// <summary>Counts how often the underlying store is asked, and can run a side effect while it resolves.</summary>
    private sealed class CountingStore(IPermissionStore inner) : IPermissionStore
    {
        public int Calls { get; private set; }

        public Func<Task>? DuringResolve { get; set; }

        public async ValueTask<PermissionSet> GetEffectivePermissionsAsync(Principal principal, CancellationToken cancellationToken)
        {
            Calls++;
            var resolved = await inner.GetEffectivePermissionsAsync(principal, cancellationToken);
            if (DuringResolve is { } sideEffect)
            {
                DuringResolve = null;
                await sideEffect();
            }

            return resolved;
        }
    }

    private sealed class Rig : IAsyncDisposable
    {
        private readonly SqliteTestDatabase _database;

        private Rig(SqliteTestDatabase database)
        {
            _database = database;
            Context = database.CreateContext(tenantId: null);
            Inner = new CountingStore(new DbPermissionStore(Context));
            Cache = new PermissionCache();
            Stats = new PermissionCacheStatistics();
            Store = new CachingPermissionStore(Inner, Context, Cache, Stats);
        }

        public RbacDbContext Context { get; }

        public CountingStore Inner { get; }

        public PermissionCache Cache { get; }

        public PermissionCacheStatistics Stats { get; }

        public CachingPermissionStore Store { get; }

        public static async Task<Rig> CreateAsync() => new(await SqliteTestDatabase.CreateAsync());

        public async Task BumpFromAnotherInstanceAsync(string tenantId)
        {
            await using var other = _database.CreateContext(tenantId: null);
            await PermissionEpoch.BumpAsync(other, tenantId, CancellationToken.None);
        }

        public async Task ExecuteFromAnotherInstanceAsync(Func<RbacDbContext, Task> action)
        {
            await using var other = _database.CreateContext(tenantId: null);
            await action(other);
        }

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await _database.DisposeAsync();
        }
    }

    [Fact]
    public async Task The_first_request_resolves_from_the_database_and_the_next_is_a_hit()
    {
        await using var rig = await Rig.CreateAsync();

        var first = await rig.Store.GetEffectivePermissionsAsync(Staff, CancellationToken.None);
        var second = await rig.Store.GetEffectivePermissionsAsync(Staff, CancellationToken.None);

        second.ShouldBeSameAs(first);
        rig.Inner.Calls.ShouldBe(1);
        (rig.Stats.Hits, rig.Stats.Misses, rig.Stats.Invalidations).ShouldBe((1, 1, 0));
        rig.Stats.EpochReads.ShouldBe(2, "one single-row read per request, hit or miss");
    }

    [Fact]
    public async Task A_bumped_epoch_is_a_miss_that_returns_the_new_permissions_and_counts_as_an_invalidation()
    {
        await using var rig = await Rig.CreateAsync();
        var before = await rig.Store.GetEffectivePermissionsAsync(Staff, CancellationToken.None);
        before.Has(Permissions.BookingsCancel).ShouldBeTrue();

        await rig.ExecuteFromAnotherInstanceAsync(async other =>
        {
            other.UserPermissions.Add(new Rbac.Persistence.Entities.UserPermissionEntity
            {
                TenantId = Staff.TenantId,
                UserId = Staff.UserId,
                PermissionKey = Permissions.BookingsCancel,
                Effect = Rbac.Persistence.Entities.PermissionEffect.Revoke,
            });
            await other.SaveChangesAsync();
            await PermissionEpoch.BumpAsync(other, Staff.TenantId, CancellationToken.None);
        });

        var after = await rig.Store.GetEffectivePermissionsAsync(Staff, CancellationToken.None);

        after.Has(Permissions.BookingsCancel).ShouldBeFalse();
        (rig.Stats.Hits, rig.Stats.Misses, rig.Stats.Invalidations).ShouldBe((0, 2, 1));
    }

    [Fact]
    public async Task Without_an_epoch_bump_a_cached_answer_is_kept_which_is_the_contract_for_out_of_band_writes()
    {
        await using var rig = await Rig.CreateAsync();
        await rig.Store.GetEffectivePermissionsAsync(Staff, CancellationToken.None);

        await rig.ExecuteFromAnotherInstanceAsync(async other =>
            await other.RolePermissions.IgnoreQueryFilters().Where(rp => rp.TenantId == Staff.TenantId && rp.RoleKey == RoleKeys.AgencyStaff && rp.PermissionKey == Permissions.BookingsCancel).ExecuteDeleteAsync());

        (await rig.Store.GetEffectivePermissionsAsync(Staff, CancellationToken.None)).Has(Permissions.BookingsCancel).ShouldBeTrue("stale until the epoch moves");

        await rig.BumpFromAnotherInstanceAsync(Staff.TenantId);

        (await rig.Store.GetEffectivePermissionsAsync(Staff, CancellationToken.None)).Has(Permissions.BookingsCancel).ShouldBeFalse();
    }

    [Fact]
    public async Task A_bump_in_another_tenant_does_not_invalidate_this_tenants_entries()
    {
        await using var rig = await Rig.CreateAsync();
        await rig.Store.GetEffectivePermissionsAsync(Staff, CancellationToken.None);

        await rig.BumpFromAnotherInstanceAsync(SeedIds.TenantB);
        await rig.Store.GetEffectivePermissionsAsync(Staff, CancellationToken.None);

        rig.Inner.Calls.ShouldBe(1);
        rig.Stats.Hits.ShouldBe(1);
    }

    [Fact]
    public async Task An_entry_is_stamped_with_the_epoch_read_before_resolving_so_a_write_during_resolution_is_never_missed()
    {
        await using var rig = await Rig.CreateAsync();
        rig.Inner.DuringResolve = () => rig.BumpFromAnotherInstanceAsync(Staff.TenantId);

        await rig.Store.GetEffectivePermissionsAsync(Staff, CancellationToken.None);
        await rig.Store.GetEffectivePermissionsAsync(Staff, CancellationToken.None);

        rig.Inner.Calls.ShouldBe(2, "the entry carries the older epoch, so the next request refreshes it");
        rig.Stats.Invalidations.ShouldBe(1);
    }

    [Fact]
    public async Task Different_users_and_roles_have_separate_entries_and_the_token_version_is_not_part_of_the_key()
    {
        await using var rig = await Rig.CreateAsync();
        var other = Principal.ForStaff(SeedIds.AgencyAdminA, SeedIds.TenantA, RoleKeys.AgencyAdmin, SeedIds.AgencyA1);

        var staff = await rig.Store.GetEffectivePermissionsAsync(Staff, CancellationToken.None);
        var admin = await rig.Store.GetEffectivePermissionsAsync(other, CancellationToken.None);
        await rig.Store.GetEffectivePermissionsAsync(Staff with { TokenVersion = 7 }, CancellationToken.None);

        staff.Has(Permissions.UsersManage).ShouldBeFalse();
        admin.Has(Permissions.UsersManage).ShouldBeTrue();
        rig.Inner.Calls.ShouldBe(2);
        rig.Cache.Count.ShouldBe(2);
    }

    [Fact]
    public async Task Anonymous_callers_get_nothing_without_touching_the_database()
    {
        await using var rig = await Rig.CreateAsync();

        (await rig.Store.GetEffectivePermissionsAsync(Principal.Anonymous, CancellationToken.None)).ShouldBeEmpty();

        rig.Stats.EpochReads.ShouldBe(0);
        rig.Inner.Calls.ShouldBe(0);
    }

    [Fact]
    public void The_cache_is_bounded_and_never_replaces_a_newer_entry_with_an_older_one()
    {
        var cache = new PermissionCache(capacity: 2);
        var set = PermissionSet.Empty;

        cache.Set("a", new CachedPermissions(5, set));
        cache.Set("a", new CachedPermissions(3, set));
        cache.TryGet("a", out var kept).ShouldBeTrue();
        kept.Epoch.ShouldBe(5);

        cache.Set("b", new CachedPermissions(1, set));
        cache.Set("c", new CachedPermissions(1, set));

        cache.Count.ShouldBeLessThanOrEqualTo(2);
        cache.TryGet("c", out _).ShouldBeTrue();
    }

    [Fact]
    public async Task Bumping_all_tenants_creates_missing_rows_and_increments_existing_ones()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(tenantId: null);
        // Demo seeding gave both tenants an epoch row (1); take tenant B's away to stand for a tenant that has none yet.
        await db.PermissionEpochs.Where(e => e.TenantId == SeedIds.TenantB).ExecuteDeleteAsync(CancellationToken.None);
        await PermissionEpoch.BumpAsync(db, SeedIds.TenantA, CancellationToken.None);
        await PermissionEpoch.BumpAsync(db, SeedIds.TenantA, CancellationToken.None);

        await PermissionEpoch.BumpAllAsync(db, CancellationToken.None);

        (await PermissionEpoch.ReadAsync(db, SeedIds.TenantA, CancellationToken.None)).ShouldBe(4);
        (await PermissionEpoch.ReadAsync(db, SeedIds.TenantB, CancellationToken.None)).ShouldBe(1, "a tenant without a row must not be skipped");
        (await PermissionEpoch.ReadAsync(db, "unknown-tenant", CancellationToken.None)).ShouldBe(0);
    }

    [Fact]
    public async Task Concurrent_bumps_from_separate_connections_are_never_lost()
    {
        using var file = new SqliteFileDatabase();
        var services = new ServiceCollection();
        services.AddScoped<ITenantContext>(_ => FixedTenantContext.None);
        services.AddDbContext<RbacDbContext>(options => options.UseSqlite(file.ConnectionString));
        await using var provider = services.BuildServiceProvider();
        await using (var scope = provider.CreateAsyncScope())
        {
            await SqliteSchema.CreateAsync(scope.ServiceProvider.GetRequiredService<RbacDbContext>(), CancellationToken.None);
        }

        await Task.WhenAll(Enumerable.Range(0, 60).Select(_ => Task.Run(
            async () =>
            {
                await using var scope = provider.CreateAsyncScope();
                await PermissionEpoch.BumpAsync(scope.ServiceProvider.GetRequiredService<RbacDbContext>(), "t1", CancellationToken.None);
            },
            TestContext.Current.CancellationToken)));

        await using var reader = provider.CreateAsyncScope();
        (await PermissionEpoch.ReadAsync(reader.ServiceProvider.GetRequiredService<RbacDbContext>(), "t1", CancellationToken.None)).ShouldBe(60);
    }
}
