using Microsoft.EntityFrameworkCore;
using Rbac.Core.Catalog;
using Rbac.Persistence;
using Rbac.Persistence.Seeding;
using Rbac.Tests.Support;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Persistence;

public class RoleCatalogStoreTests
{
    [Fact]
    public async Task A_tenants_stored_catalog_round_trips_to_the_code_catalog()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(tenantId: null);
        var code = DefaultRoleCatalog.Create();

        var loaded = await RoleCatalogStore.LoadAsync(db, SeedIds.TenantA, TestContext.Current.CancellationToken);

        loaded.Roles.Count.ShouldBe(code.Roles.Count);
        foreach (var expected in code.Roles)
        {
            var actual = loaded.Find(expected.Key);
            actual.ShouldNotBeNull(expected.Key);
            actual.Family.ShouldBe(expected.Family);
            actual.DefaultPermissions.ShouldBe(expected.DefaultPermissions, ignoreOrder: true);
            actual.CreatableRoleKeys.ShouldBe(expected.CreatableRoleKeys, ignoreOrder: true);
        }
    }

    [Fact]
    public async Task The_structure_only_catalog_has_every_role_and_no_defaults_because_defaults_differ_per_tenant()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(tenantId: null);
        var code = DefaultRoleCatalog.Create();

        var loaded = await RoleCatalogStore.LoadStructureAsync(db, TestContext.Current.CancellationToken);

        loaded.Roles.Select(r => r.Key).ShouldBe(code.Roles.Select(r => r.Key));
        loaded.Roles.ShouldAllBe(r => r.DefaultPermissions.Count == 0);
        loaded.Find(RoleKeys.AgencyAdmin)!.IsAdmin.ShouldBeTrue();
        loaded.Find(RoleKeys.AgencyAdmin)!.CreatableRoleKeys.ShouldBe(code.Find(RoleKeys.AgencyAdmin)!.CreatableRoleKeys, ignoreOrder: true);
    }

    [Fact]
    public async Task One_tenants_edit_is_invisible_in_another_tenants_loaded_catalog_and_an_unknown_tenant_grants_nothing()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(tenantId: null);
        await db.RolePermissions
            .IgnoreQueryFilters()
            .Where(rp => rp.TenantId == SeedIds.TenantB && rp.RoleKey == RoleKeys.AgencyStaff && rp.PermissionKey == Permissions.BookingsCancel)
            .ExecuteDeleteAsync(TestContext.Current.CancellationToken);

        var tenantA = await RoleCatalogStore.LoadAsync(db, SeedIds.TenantA, TestContext.Current.CancellationToken);
        var tenantB = await RoleCatalogStore.LoadAsync(db, SeedIds.TenantB, TestContext.Current.CancellationToken);
        var nobody = await RoleCatalogStore.LoadAsync(db, "tenant-that-does-not-exist", TestContext.Current.CancellationToken);

        tenantA.Find(RoleKeys.AgencyStaff)!.DefaultPermissions.ShouldContain(Permissions.BookingsCancel);
        tenantB.Find(RoleKeys.AgencyStaff)!.DefaultPermissions.ShouldNotContain(Permissions.BookingsCancel);
        nobody.Roles.ShouldAllBe(r => r.DefaultPermissions.Count == 0);
    }
}
