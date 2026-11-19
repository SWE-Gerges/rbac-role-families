using Microsoft.EntityFrameworkCore;
using Rbac.Abstractions;
using Rbac.Core.Catalog;
using Rbac.Core.Users;
using Rbac.Persistence;
using Rbac.Persistence.Caching;
using Rbac.Persistence.Entities;
using Rbac.Persistence.Seeding;
using Rbac.Tests.Support;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Persistence;

public class PermissionSeederTests
{
    private const string Export = "bookings.export";
    private const string TenantC = "tenant-c";

    private static RoleCatalog Version2 => DefaultRoleCatalog.Create();

    private static int DefaultCount => Version2.Roles.Sum(r => r.DefaultPermissions.Count);

    /// <summary>The next catalog version: a new permission handed to two roles, and optionally a structure change.</summary>
    private static RoleCatalog Version3(Func<RoleDefinition, RoleDefinition>? change = null) => RoleCatalog.FromDefinitions(
        Version2.Roles.Select(role =>
        {
            var next = role.Key is RoleKeys.AgencyAdmin or RoleKeys.SystemAdmin
                ? role with { DefaultPermissions = new HashSet<string>(role.DefaultPermissions) { Export } }
                : role;
            return change is null ? next : change(next);
        }),
        version: 3);

    private static async Task<string> SnapshotAsync(RbacDbContext db)
    {
        var ct = TestContext.Current.CancellationToken;
        var parts = new List<string>
        {
            "permissions: " + string.Join(';', (await db.Permissions.OrderBy(p => p.Key).ToListAsync(ct)).Select(p => $"{p.Key}={p.Description}")),
            "roles: " + string.Join(';', (await db.Roles.OrderBy(r => r.Key).ToListAsync(ct)).Select(r => $"{r.Key}|{r.Family}|{r.IsAdmin}|{r.SortOrder}|{string.Join(',', r.CreatableRoleKeys)}")),
            "defaults: " + string.Join(';', (await db.RolePermissions.IgnoreQueryFilters().OrderBy(r => r.TenantId).ThenBy(r => r.RoleKey).ThenBy(r => r.PermissionKey).ToListAsync(ct)).Select(r => $"{r.TenantId}/{r.RoleKey}:{r.PermissionKey}")),
            "seeded: " + string.Join(';', (await db.RoleDefaultSeeds.OrderBy(r => r.TenantId).ThenBy(r => r.RoleKey).ThenBy(r => r.PermissionKey).ToListAsync(ct)).Select(r => $"{r.TenantId}/{r.RoleKey}:{r.PermissionKey}@{r.SeededInVersion}")),
            "version: " + string.Join(';', (await db.CatalogVersions.ToListAsync(ct)).Select(v => $"{v.Name}={v.Version}")),
            "epochs: " + string.Join(';', (await db.PermissionEpochs.OrderBy(e => e.TenantId).ToListAsync(ct)).Select(e => $"{e.TenantId}={e.Epoch}")),
            "overrides: " + string.Join(';', (await db.UserPermissions.IgnoreQueryFilters().OrderBy(u => u.UserId).ThenBy(u => u.PermissionKey).ToListAsync(ct)).Select(u => $"{u.UserId}:{u.PermissionKey}:{u.Effect}")),
        };
        return string.Join(Environment.NewLine, parts);
    }

    private static string Section(string snapshot, string name) =>
        snapshot.Split(Environment.NewLine).Single(line => line.StartsWith(name + ":", StringComparison.Ordinal));

    /// <summary>The "defaults" section of a snapshot restricted to one tenant.</summary>
    private static string DefaultsOf(string snapshot, string tenantId) =>
        string.Join(';', Section(snapshot, "defaults").Split(';').Where(e => e.Contains($"{tenantId}/", StringComparison.Ordinal)));

    private static async Task<IReadOnlySet<string>> DefaultsOfAsync(RbacDbContext db, string tenantId, string roleKey) =>
        (await db.RolePermissions.IgnoreQueryFilters()
            .Where(rp => rp.TenantId == tenantId && rp.RoleKey == roleKey)
            .Select(rp => rp.PermissionKey)
            .ToListAsync(TestContext.Current.CancellationToken))
        .ToHashSet(StringComparer.Ordinal);

    private static Task RemoveDefaultAsync(RbacDbContext db, string tenantId, string roleKey, string permission) =>
        db.RolePermissions.IgnoreQueryFilters()
            .Where(rp => rp.TenantId == tenantId && rp.RoleKey == roleKey && rp.PermissionKey == permission)
            .ExecuteDeleteAsync(TestContext.Current.CancellationToken);

    private static async Task AddTenantsAsync(RbacDbContext db, params string[] ids)
    {
        db.Tenants.AddRange(ids.Select(id => new TenantEntity { Id = id, Name = id }));
        await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    private static async Task<PermissionSet> PermissionsOfAsync(SqliteTestDatabase database, Principal principal)
    {
        await using var db = database.CreateContext(principal.TenantId);
        return await new DbPermissionStore(db).GetEffectivePermissionsAsync(principal, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task A_first_run_stores_the_catalog_gives_every_tenant_its_own_defaults_and_records_what_it_handed_out()
    {
        await using var database = await SqliteTestDatabase.CreateAsync(seed: false, seedCatalog: false);
        await using var db = database.CreateContext(tenantId: null);
        await AddTenantsAsync(db, SeedIds.TenantA, SeedIds.TenantB);

        var result = await PermissionSeeder.SeedAsync(db, Version2, TestContext.Current.CancellationToken);

        result.PermissionsAdded.ShouldBe(Permissions.All.Count);
        result.RolesAdded.ShouldBe(9);
        result.DefaultsAdded.ShouldBe(DefaultCount * 2);
        (await db.RoleDefaultSeeds.CountAsync(TestContext.Current.CancellationToken)).ShouldBe(DefaultCount * 2);
        (await db.CatalogVersions.SingleAsync(TestContext.Current.CancellationToken)).Version.ShouldBe(2);
        foreach (var tenant in new[] { SeedIds.TenantA, SeedIds.TenantB })
        {
            var loaded = await RoleCatalogStore.LoadAsync(db, tenant, TestContext.Current.CancellationToken);
            foreach (var role in Version2.Roles)
            {
                loaded.Find(role.Key)!.DefaultPermissions.ShouldBe(role.DefaultPermissions, ignoreOrder: true, customMessage: $"{tenant}/{role.Key}");
                loaded.Find(role.Key)!.IsAdmin.ShouldBe(role.IsAdmin);
            }
        }
    }

    [Fact]
    public async Task Running_twice_leaves_identical_state_and_the_second_run_reports_no_change_and_moves_no_epoch()
    {
        await using var database = await SqliteTestDatabase.CreateAsync(seed: false, seedCatalog: false);
        await using var db = database.CreateContext(tenantId: null);
        await AddTenantsAsync(db, SeedIds.TenantA, SeedIds.TenantB);

        var first = await PermissionSeeder.SeedAsync(db, Version2, TestContext.Current.CancellationToken);
        var afterFirst = await SnapshotAsync(db);
        var second = await PermissionSeeder.SeedAsync(db, Version2, TestContext.Current.CancellationToken);
        var afterSecond = await SnapshotAsync(db);

        first.Changed.ShouldBeTrue();
        second.ShouldBe(new PermissionSeedResult(0, 0, 0, 0, 0));
        afterSecond.ShouldBe(afterFirst);
        (await PermissionEpoch.ReadAsync(db, SeedIds.TenantA, TestContext.Current.CancellationToken)).ShouldBe(1, "bumped once by the first run only");
        (await PermissionEpoch.ReadAsync(db, SeedIds.TenantB, TestContext.Current.CancellationToken)).ShouldBe(1);
    }

    [Fact]
    public async Task A_permission_an_administrator_removed_from_a_role_is_never_handed_out_again_in_that_tenant_and_other_tenants_keep_theirs()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(tenantId: null);
        await RemoveDefaultAsync(db, SeedIds.TenantA, RoleKeys.AgencyStaff, Permissions.BookingsCancel);

        var again = await PermissionSeeder.SeedAsync(db, Version2, TestContext.Current.CancellationToken);
        var upgraded = await PermissionSeeder.SeedAsync(db, Version3(), TestContext.Current.CancellationToken);

        again.DefaultsAdded.ShouldBe(0);
        (await DefaultsOfAsync(db, SeedIds.TenantA, RoleKeys.AgencyStaff)).ShouldNotContain(Permissions.BookingsCancel);
        (await DefaultsOfAsync(db, SeedIds.TenantB, RoleKeys.AgencyStaff)).ShouldContain(Permissions.BookingsCancel);
        upgraded.DefaultsAdded.ShouldBe(4, "only the new permission, for the two roles that got it, in each of the two tenants");
        (await DefaultsOfAsync(db, SeedIds.TenantA, RoleKeys.AgencyStaff)).ShouldNotContain(Permissions.BookingsCancel);
    }

    [Fact]
    public async Task A_permission_an_administrator_added_to_a_role_is_never_taken_away()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(tenantId: null);
        db.RolePermissions.Add(new RolePermissionEntity { TenantId = SeedIds.TenantA, RoleKey = RoleKeys.CorporateStaff, PermissionKey = Permissions.ReportsView });
        await db.SaveChangesAsync(TestContext.Current.CancellationToken);

        await PermissionSeeder.SeedAsync(db, Version3(), TestContext.Current.CancellationToken);

        (await DefaultsOfAsync(db, SeedIds.TenantA, RoleKeys.CorporateStaff)).ShouldContain(Permissions.ReportsView);
        (await DefaultsOfAsync(db, SeedIds.TenantB, RoleKeys.CorporateStaff)).ShouldNotContain(Permissions.ReportsView);
    }

    [Fact]
    public async Task A_later_version_adds_new_permissions_to_the_intended_roles_in_every_tenant_and_leaves_overrides_and_edits_alone()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(tenantId: null);
        await RemoveDefaultAsync(db, SeedIds.TenantA, RoleKeys.AgencyStaff, Permissions.BookingsCancel);
        var before = await SnapshotAsync(db);

        var result = await PermissionSeeder.SeedAsync(db, Version3(), TestContext.Current.CancellationToken);

        result.PermissionsAdded.ShouldBe(1);
        result.DefaultsAdded.ShouldBe(4);
        foreach (var tenant in new[] { SeedIds.TenantA, SeedIds.TenantB })
        {
            foreach (var role in Version2.Roles)
            {
                var defaults = await DefaultsOfAsync(db, tenant, role.Key);
                defaults.Contains(Export).ShouldBe(role.Key is RoleKeys.AgencyAdmin or RoleKeys.SystemAdmin, $"{tenant}/{role.Key}");
                var expected = tenant == SeedIds.TenantA && role.Key == RoleKeys.AgencyStaff
                    ? role.DefaultPermissions.Where(p => p != Permissions.BookingsCancel)
                    : role.DefaultPermissions;
                defaults.Where(p => p != Export).ShouldBe(expected, ignoreOrder: true, customMessage: $"{tenant}/{role.Key}: existing grants and admin edits are untouched");
            }
        }

        var after = await SnapshotAsync(db);
        Section(after, "overrides").ShouldBe(Section(before, "overrides"), "per-user overrides are never touched");
        (await db.CatalogVersions.SingleAsync(TestContext.Current.CancellationToken)).Version.ShouldBe(3);
        (await db.RoleDefaultSeeds.Where(s => s.PermissionKey == Export).Select(s => s.SeededInVersion).Distinct().ToListAsync(TestContext.Current.CancellationToken)).ShouldBe([3]);
        (await PermissionEpoch.ReadAsync(db, SeedIds.TenantA, TestContext.Current.CancellationToken)).ShouldBe(2, "one from demo seeding, one from this run");
        (await PermissionEpoch.ReadAsync(db, SeedIds.TenantB, TestContext.Current.CancellationToken)).ShouldBe(2);

        (await PermissionSeeder.SeedAsync(db, Version3(), TestContext.Current.CancellationToken)).Changed.ShouldBeFalse();
        (await SnapshotAsync(db)).ShouldBe(after);
    }

    [Fact]
    public async Task Role_structure_follows_the_code_only_when_the_catalog_version_goes_up()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(tenantId: null);
        static RoleDefinition PromoteInternalStaff(RoleDefinition role) => role.Key == RoleKeys.InternalStaff ? role with { IsAdmin = true } : role;
        var sameVersion = RoleCatalog.FromDefinitions(Version2.Roles.Select(PromoteInternalStaff), version: 2);

        var unchanged = await PermissionSeeder.SeedAsync(db, sameVersion, TestContext.Current.CancellationToken);
        (await db.Roles.SingleAsync(r => r.Key == RoleKeys.InternalStaff, TestContext.Current.CancellationToken)).IsAdmin.ShouldBeFalse("same version: stored structure is left as it is");
        unchanged.RolesUpdated.ShouldBe(0);

        var upgraded = await PermissionSeeder.SeedAsync(db, Version3(PromoteInternalStaff), TestContext.Current.CancellationToken);
        (await db.Roles.SingleAsync(r => r.Key == RoleKeys.InternalStaff, TestContext.Current.CancellationToken)).IsAdmin.ShouldBeTrue();
        upgraded.RolesUpdated.ShouldBe(1);
    }

    [Fact]
    public async Task A_bad_stored_family_is_not_repaired_when_the_version_is_unchanged_so_startup_validation_can_report_it()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(tenantId: null);
        await db.Database.ExecuteSqlRawAsync("UPDATE \"Role\" SET \"Family\" = 'Galaxy' WHERE \"Key\" = 'agency-staff'", TestContext.Current.CancellationToken);

        await PermissionSeeder.SeedAsync(db, Version2, TestContext.Current.CancellationToken);

        (await RoleCatalogStore.LoadStructureAsync(db, TestContext.Current.CancellationToken)).Find(RoleKeys.AgencyStaff)!.Family.ShouldBe(default);
    }

    [Fact]
    public async Task Permission_descriptions_are_upserted_by_key()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(tenantId: null);
        await db.Database.ExecuteSqlRawAsync("UPDATE \"Permission\" SET \"Description\" = 'stale' WHERE \"Key\" = 'bookings.read'", TestContext.Current.CancellationToken);

        var result = await PermissionSeeder.SeedAsync(db, Version2, TestContext.Current.CancellationToken);

        result.PermissionsUpdated.ShouldBe(1);
        (await db.Permissions.SingleAsync(p => p.Key == Permissions.BookingsRead, TestContext.Current.CancellationToken)).Description.ShouldBe(Permissions.Describe(Permissions.BookingsRead));
    }

    [Fact]
    public async Task A_database_from_before_seed_tracking_keeps_its_defaults_and_gains_the_ones_it_lacks_per_tenant()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(tenantId: null);
        // What an earlier version left behind: role rows without seed records, a version row or some of today's defaults.
        await db.RoleDefaultSeeds.ExecuteDeleteAsync(TestContext.Current.CancellationToken);
        await db.CatalogVersions.ExecuteDeleteAsync(TestContext.Current.CancellationToken);
        await RemoveDefaultAsync(db, SeedIds.TenantA, RoleKeys.AgencyAdmin, Permissions.UsersRead);
        db.RolePermissions.Add(new RolePermissionEntity { TenantId = SeedIds.TenantA, RoleKey = RoleKeys.AgencyStaff, PermissionKey = Permissions.ReportsView });
        await db.SaveChangesAsync(TestContext.Current.CancellationToken);

        var result = await PermissionSeeder.SeedAsync(db, Version2, TestContext.Current.CancellationToken);

        result.DefaultsAdded.ShouldBe(1);
        (await DefaultsOfAsync(db, SeedIds.TenantA, RoleKeys.AgencyAdmin)).ShouldContain(Permissions.UsersRead);
        (await DefaultsOfAsync(db, SeedIds.TenantA, RoleKeys.AgencyStaff)).ShouldContain(Permissions.ReportsView, "an existing extra grant is kept");
        (await db.CatalogVersions.SingleAsync(TestContext.Current.CancellationToken)).Version.ShouldBe(2);
    }

    [Fact]
    public async Task A_brand_new_tenant_has_no_defaults_and_so_no_permissions_until_it_is_seeded_and_then_gets_exactly_the_catalog_defaults()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using (var setup = database.CreateContext(tenantId: null))
        {
            await AddTenantsAsync(setup, TenantC);
            setup.Users.Add(new User { Id = "c-system-admin", TenantId = TenantC, Handle = "c-system-admin", DisplayName = "C admin", Kind = PrincipalKind.Staff, RoleKey = RoleKeys.SystemAdmin });
            setup.Users.Add(new User { Id = "c-agency-staff", TenantId = TenantC, Handle = "c-agency-staff", DisplayName = "C staff", Kind = PrincipalKind.Staff, RoleKey = RoleKeys.AgencyStaff, AgencyId = "agency-c1" });
            await setup.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        var admin = Principal.ForStaff("c-system-admin", TenantC, RoleKeys.SystemAdmin);
        await using var db = database.CreateContext(tenantId: null);
        var before = await SnapshotAsync(db);
        (await PermissionsOfAsync(database, admin)).ShouldBeEmpty("deny by default: no defaults, no permissions");

        var result = await PermissionSeeder.SeedTenantAsync(db, TenantC, Version2, TestContext.Current.CancellationToken);

        result.DefaultsAdded.ShouldBe(DefaultCount);
        (await PermissionsOfAsync(database, admin)).ShouldBe(Version2.Find(RoleKeys.SystemAdmin)!.DefaultPermissions, ignoreOrder: true);
        (await PermissionsOfAsync(database, Principal.ForStaff("c-agency-staff", TenantC, RoleKeys.AgencyStaff, "agency-c1")))
            .ShouldBe(Version2.Find(RoleKeys.AgencyStaff)!.DefaultPermissions, ignoreOrder: true);

        var after = await SnapshotAsync(db);
        DefaultsOf(after, SeedIds.TenantA).ShouldBe(DefaultsOf(before, SeedIds.TenantA), "other tenants' defaults are not touched");
        DefaultsOf(after, SeedIds.TenantB).ShouldBe(DefaultsOf(before, SeedIds.TenantB));
        (await PermissionEpoch.ReadAsync(db, TenantC, TestContext.Current.CancellationToken)).ShouldBe(1);
        (await PermissionEpoch.ReadAsync(db, SeedIds.TenantA, TestContext.Current.CancellationToken)).ShouldBe(1, "only the new tenant's epoch moved");

        (await PermissionSeeder.SeedTenantAsync(db, TenantC, Version2, TestContext.Current.CancellationToken)).Changed.ShouldBeFalse();
        (await PermissionEpoch.ReadAsync(db, TenantC, TestContext.Current.CancellationToken)).ShouldBe(1);
        await Should.ThrowAsync<InvalidOperationException>(() => PermissionSeeder.SeedTenantAsync(db, "no-such-tenant", Version2, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task A_brand_new_tenant_gets_the_catalog_defaults_and_never_another_tenants_edits_whichever_way_it_is_seeded()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(tenantId: null);
        await RemoveDefaultAsync(db, SeedIds.TenantA, RoleKeys.AgencyStaff, Permissions.BookingsCancel);
        db.RolePermissions.Add(new RolePermissionEntity { TenantId = SeedIds.TenantA, RoleKey = RoleKeys.CorporateStaff, PermissionKey = Permissions.ReportsView });
        await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        await AddTenantsAsync(db, "tenant-d");

        var nextStart = await PermissionSeeder.SeedAsync(db, Version2, TestContext.Current.CancellationToken);

        nextStart.DefaultsAdded.ShouldBe(DefaultCount, "the next run of the seeder gives the new tenant everything, and only that tenant");
        var loaded = await RoleCatalogStore.LoadAsync(db, "tenant-d", TestContext.Current.CancellationToken);
        foreach (var role in Version2.Roles)
        {
            loaded.Find(role.Key)!.DefaultPermissions.ShouldBe(role.DefaultPermissions, ignoreOrder: true, customMessage: role.Key);
        }

        (await DefaultsOfAsync(db, SeedIds.TenantA, RoleKeys.AgencyStaff)).ShouldNotContain(Permissions.BookingsCancel, "tenant A's edit stays tenant A's");
        (await DefaultsOfAsync(db, SeedIds.TenantA, RoleKeys.CorporateStaff)).ShouldContain(Permissions.ReportsView);
        (await DefaultsOfAsync(db, "tenant-d", RoleKeys.CorporateStaff)).ShouldNotContain(Permissions.ReportsView);
    }
}
