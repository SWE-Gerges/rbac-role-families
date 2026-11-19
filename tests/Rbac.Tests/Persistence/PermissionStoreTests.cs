using Microsoft.EntityFrameworkCore;
using Rbac.Abstractions;
using Rbac.Core.Catalog;
using Rbac.Persistence;
using Rbac.Persistence.Entities;
using Rbac.Persistence.Seeding;
using Rbac.Tests.Support;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Persistence;

public class PermissionStoreTests
{
    private static async Task<PermissionSet> PermissionsOf(SqliteTestDatabase database, Principal principal)
    {
        await using var db = database.CreateContext(principal.IsAnonymous ? null : principal.TenantId);
        return await new DbPermissionStore(db).GetEffectivePermissionsAsync(principal, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task A_role_resolves_to_its_stored_defaults()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();

        var permissions = await PermissionsOf(database, SeedPrincipals.From(SeedPrincipals.User(SeedIds.AgencyStaffA)));

        permissions.ShouldBe([Permissions.BookingsRead, Permissions.BookingsCreate, Permissions.BookingsCancel], ignoreOrder: true);
    }

    [Fact]
    public async Task A_per_user_grant_adds_to_the_role_defaults()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();

        var plain = await PermissionsOf(database, SeedPrincipals.From(SeedPrincipals.User(SeedIds.AgencyStaffA)));
        var granted = await PermissionsOf(database, SeedPrincipals.From(SeedPrincipals.User(SeedIds.AgencyStaffViewAllA)));

        plain.Has(Permissions.BookingsViewAllAgency).ShouldBeFalse();
        granted.Has(Permissions.BookingsViewAllAgency).ShouldBeTrue();
        granted.Has(Permissions.BookingsRead).ShouldBeTrue();
    }

    [Fact]
    public async Task A_per_user_revoke_removes_a_role_default()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using (var db = database.CreateContext(SeedIds.TenantA))
        {
            db.UserPermissions.Add(new UserPermissionEntity
            {
                TenantId = SeedIds.TenantA,
                UserId = SeedIds.InternalStaffA,
                PermissionKey = Permissions.BookingsCancel,
                Effect = PermissionEffect.Revoke,
            });
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        var permissions = await PermissionsOf(database, SeedPrincipals.From(SeedPrincipals.User(SeedIds.InternalStaffA)));

        permissions.Has(Permissions.BookingsCancel).ShouldBeFalse();
        permissions.Has(Permissions.BookingsRead).ShouldBeTrue();
    }

    [Fact]
    public async Task Permissions_are_resolved_live_on_every_call()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var principal = SeedPrincipals.From(SeedPrincipals.User(SeedIds.AgencyStaffA));

        (await PermissionsOf(database, principal)).Has(Permissions.BookingsCancel).ShouldBeTrue();

        await using (var db = database.CreateContext(null))
        {
            await db.RolePermissions
                .IgnoreQueryFilters()
                .Where(rp => rp.TenantId == SeedIds.TenantA && rp.RoleKey == RoleKeys.AgencyStaff && rp.PermissionKey == Permissions.BookingsCancel)
                .ExecuteDeleteAsync(TestContext.Current.CancellationToken);
        }

        (await PermissionsOf(database, principal)).Has(Permissions.BookingsCancel).ShouldBeFalse();
    }

    [Fact]
    public async Task Role_defaults_are_read_for_the_principals_own_tenant_only()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var tenantA = SeedPrincipals.From(SeedPrincipals.User(SeedIds.AgencyStaffA));
        var tenantB = SeedPrincipals.From(SeedPrincipals.User(SeedIds.AgencyStaffB));

        await using (var db = database.CreateContext(null))
        {
            await db.RolePermissions
                .IgnoreQueryFilters()
                .Where(rp => rp.TenantId == SeedIds.TenantB && rp.RoleKey == RoleKeys.AgencyStaff && rp.PermissionKey == Permissions.BookingsCancel)
                .ExecuteDeleteAsync(TestContext.Current.CancellationToken);
        }

        (await PermissionsOf(database, tenantB)).Has(Permissions.BookingsCancel).ShouldBeFalse();
        (await PermissionsOf(database, tenantA)).Has(Permissions.BookingsCancel).ShouldBeTrue("tenant A's copy of the role defaults is untouched");
    }

    [Fact]
    public async Task Customers_get_the_customer_defaults_and_no_staff_permissions()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();

        var permissions = await PermissionsOf(database, SeedPrincipals.From(SeedPrincipals.User(SeedIds.CustomerA)));

        permissions.ShouldBe(Permissions.CustomerDefaults, ignoreOrder: true);
    }

    [Fact]
    public async Task Anonymous_unknown_and_other_tenant_callers_have_no_permissions()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();

        (await PermissionsOf(database, Principal.Anonymous)).ShouldBeEmpty();
        (await PermissionsOf(database, Principal.ForStaff("ghost", SeedIds.TenantA, RoleKeys.SystemAdmin))).ShouldBeEmpty();
        (await PermissionsOf(database, Principal.ForStaff(SeedIds.SystemAdminA, SeedIds.TenantB, RoleKeys.SystemAdmin)))
            .ShouldBeEmpty("a user id from tenant a does not exist in tenant b");
    }

    [Fact]
    public async Task A_token_whose_role_no_longer_matches_the_stored_role_resolves_to_nothing()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var staleToken = Principal.ForStaff(SeedIds.AgencyStaffA, SeedIds.TenantA, RoleKeys.SystemAdmin, SeedIds.AgencyA1);

        (await PermissionsOf(database, staleToken)).ShouldBeEmpty();
    }

    [Fact]
    public async Task A_customer_token_for_a_staff_user_and_the_reverse_resolve_to_nothing()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();

        (await PermissionsOf(database, Principal.ForCustomer(SeedIds.AgencyStaffA, SeedIds.TenantA))).ShouldBeEmpty();
        (await PermissionsOf(database, Principal.ForStaff(SeedIds.CustomerA, SeedIds.TenantA, RoleKeys.SystemAdmin))).ShouldBeEmpty();
    }

    [Fact]
    public async Task A_deactivated_user_has_no_permissions()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using (var db = database.CreateContext(SeedIds.TenantA))
        {
            await db.Users.Where(u => u.Id == SeedIds.AgencyStaffA)
                .ExecuteUpdateAsync(s => s.SetProperty(u => u.IsActive, false), TestContext.Current.CancellationToken);
        }

        (await PermissionsOf(database, SeedPrincipals.From(SeedPrincipals.User(SeedIds.AgencyStaffA)))).ShouldBeEmpty();
    }

    [Fact]
    public async Task A_soft_deleted_user_resolves_to_nothing_even_with_a_principal_that_still_looks_valid()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var principal = SeedPrincipals.From(SeedPrincipals.User(SeedIds.AgencyStaffViewAllA));
        (await PermissionsOf(database, principal)).ShouldNotBeEmpty();

        await using (var db = database.CreateContext(SeedIds.TenantA))
        {
            await db.Users.Where(u => u.Id == SeedIds.AgencyStaffViewAllA)
                .ExecuteUpdateAsync(s => s.SetProperty(u => u.DeletedAt, new DateTimeOffset(2026, 3, 1, 0, 0, 0, TimeSpan.Zero)), TestContext.Current.CancellationToken);
        }

        (await PermissionsOf(database, principal)).ShouldBeEmpty();
    }

    [Fact]
    public async Task A_new_user_with_a_reused_handle_has_a_fresh_id_and_none_of_the_old_overrides()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using (var db = database.CreateContext(SeedIds.TenantA))
        {
            var old = await db.Users.SingleAsync(u => u.Id == SeedIds.AgencyStaffViewAllA, TestContext.Current.CancellationToken);
            old.DeletedAt = new DateTimeOffset(2026, 3, 1, 0, 0, 0, TimeSpan.Zero);
            db.Users.Add(new Rbac.Core.Users.User
            {
                Id = "usr-returning",
                TenantId = SeedIds.TenantA,
                Handle = old.Handle,
                DisplayName = "Returning",
                Kind = PrincipalKind.Staff,
                RoleKey = RoleKeys.AgencyStaff,
                AgencyId = SeedIds.AgencyA1,
            });
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        var returning = Principal.ForStaff("usr-returning", SeedIds.TenantA, RoleKeys.AgencyStaff, SeedIds.AgencyA1);

        (await PermissionsOf(database, returning)).Has(Permissions.BookingsViewAllAgency).ShouldBeFalse();
        (await PermissionsOf(database, returning)).Has(Permissions.BookingsRead).ShouldBeTrue();
    }
}
