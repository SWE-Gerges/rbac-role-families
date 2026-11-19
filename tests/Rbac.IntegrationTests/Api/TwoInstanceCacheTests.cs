using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Rbac.Core.Catalog;
using Rbac.Demo.Contracts;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Caching;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

/// <summary>
/// Two application instances (two hosts with their own caches) over one shared SQLite file. A change made through one must be
/// seen by the other on its very next request, and only the persisted epoch can make that happen.
/// </summary>
[Trait("Category", "Integration")]
public class TwoInstanceCacheTests
{
    private static PermissionCacheStatistics Stats(ApiFactory instance) => instance.Services.GetRequiredService<PermissionCacheStatistics>();

    private static async Task<UserPermissionsResponse> ReadAsync(HttpClient admin, string userId) =>
        await (await admin.GetAsync($"/api/v1/users/{userId}/permissions")).ReadAsAsync<UserPermissionsResponse>();

    private static async Task<HttpResponseMessage> EditAsync(HttpClient admin, string userId, int version, string[]? grant = null, string[]? revoke = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/users/{userId}/permissions")
        {
            Content = JsonContent.Create(new EditUserPermissionsRequest(grant, revoke), options: ApiFactory.Json),
        };
        request.Headers.TryAddWithoutValidation("If-Match", $"\"{version}\"");
        return await admin.SendAsync(request);
    }

    [Fact]
    public async Task A_grant_made_through_instance_a_is_served_by_instance_b_on_its_next_request_and_not_before()
    {
        using var database = SharedSqliteDatabase.CreateFile();
        using var instanceA = ApiFactory.With(new ApiFactoryOptions { Database = database });
        using var instanceB = ApiFactory.With(new ApiFactoryOptions { Database = database });
        using var adminOnA = await instanceA.ClientForAsync(SeedIds.AgencyAdminA);
        using var staffOnB = await instanceB.ClientForAsync(SeedIds.AgencyStaffA);

        // Instance B warms its cache.
        var cold = await (await staffOnB.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>();
        var misses = Stats(instanceB).Misses;
        await staffOnB.GetAsync("/api/v1/me");
        cold.Permissions.ShouldNotContain(Permissions.BookingsViewAllAgency);
        Stats(instanceB).Hits.ShouldBeGreaterThan(0, "a warm repeat is served from the cache");
        Stats(instanceB).Misses.ShouldBe(misses, "a warm repeat does not go back to the database for permissions");

        // The change goes through instance A.
        var current = await ReadAsync(adminOnA, SeedIds.AgencyStaffA);
        (await EditAsync(adminOnA, SeedIds.AgencyStaffA, current.Version, grant: [Permissions.BookingsViewAllAgency])).StatusCode.ShouldBe(HttpStatusCode.OK);

        // The staff member signs in again (the edit revoked the old session) and calls instance B.
        var invalidationsBefore = Stats(instanceB).Invalidations;
        using var freshOnB = await instanceB.ClientForAsync(SeedIds.AgencyStaffA, freshToken: true);
        var warm = await (await freshOnB.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>();

        warm.Permissions.ShouldContain(Permissions.BookingsViewAllAgency, "instance B must not serve the permissions it cached before the change");
        Stats(instanceB).Invalidations.ShouldBe(invalidationsBefore + 1);
        var (_, widened) = await ApiHelpers.ListIdsAsync(freshOnB);
        widened.Count.ShouldBeGreaterThan(4);
    }

    [Fact]
    public async Task A_revoke_through_one_instance_leaves_no_stale_grant_on_the_other()
    {
        using var database = SharedSqliteDatabase.CreateFile();
        using var instanceA = ApiFactory.With(new ApiFactoryOptions { Database = database });
        using var instanceB = ApiFactory.With(new ApiFactoryOptions { Database = database });
        using var adminOnB = await instanceB.ClientForAsync(SeedIds.AgencyAdminA);
        using var staffOnB = await instanceB.ClientForAsync(SeedIds.AgencyStaffA);
        var draft = await ApiHelpers.CreateBookingAsync(staffOnB);
        (await staffOnB.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.OK);

        using var adminOnA = await instanceA.ClientForAsync(SeedIds.AgencyAdminA);
        var current = await ReadAsync(adminOnA, SeedIds.AgencyStaffA);
        (await EditAsync(adminOnA, SeedIds.AgencyStaffA, current.Version, revoke: [Permissions.BookingsCancel])).StatusCode.ShouldBe(HttpStatusCode.OK);

        using var freshOnB = await instanceB.ClientForAsync(SeedIds.AgencyStaffA, freshToken: true);
        (await freshOnB.PostAsync($"/api/v1/bookings/{draft.Id}/cancel", null)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await staffOnB.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "the old session was revoked too");
        (await adminOnB.GetAsync($"/api/v1/users/{SeedIds.AgencyStaffA}/permissions")).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_role_default_edit_through_one_instance_reaches_that_tenant_on_the_other_instance_and_no_other_tenant()
    {
        using var database = SharedSqliteDatabase.CreateFile();
        using var instanceA = ApiFactory.With(new ApiFactoryOptions { Database = database });
        using var instanceB = ApiFactory.With(new ApiFactoryOptions { Database = database });
        using var tenantAStaffOnB = await instanceB.ClientForAsync(SeedIds.AgencyStaffA);
        using var tenantBStaffOnB = await instanceB.ClientForAsync(SeedIds.AgencyStaffB);
        (await (await tenantAStaffOnB.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>()).Permissions.ShouldContain(Permissions.BookingsCancel);
        (await (await tenantBStaffOnB.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>()).Permissions.ShouldContain(Permissions.BookingsCancel);
        var epochOfBBefore = await database.ScalarAsync("SELECT \"Epoch\" FROM \"PermissionEpoch\" WHERE \"TenantId\" = 'tenant-b'");
        using var systemOnA = await instanceA.ClientForAsync(SeedIds.SystemAdminA);
        var role = await (await systemOnA.GetAsync($"/api/v1/roles/{RoleKeys.AgencyStaff}")).ReadAsAsync<RoleResponse>();

        (await systemOnA.PutAsJsonAsync(
            $"/api/v1/roles/{RoleKeys.AgencyStaff}/permissions",
            new SetRolePermissionsRequest([.. role.Permissions.Where(p => p != Permissions.BookingsCancel)]),
            ApiFactory.Json)).StatusCode.ShouldBe(HttpStatusCode.OK);

        using var freshOnB = await instanceB.ClientForAsync(SeedIds.AgencyStaffA, freshToken: true);
        (await (await freshOnB.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>()).Permissions.ShouldNotContain(Permissions.BookingsCancel);

        // The other tenant is neither revoked nor changed, and its epoch did not move, so its warm cache entry is still good.
        var statsBefore = Stats(instanceB).Hits;
        (await (await tenantBStaffOnB.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>()).Permissions.ShouldContain(Permissions.BookingsCancel);
        Stats(instanceB).Hits.ShouldBe(statsBefore + 1, "tenant B is still served from the cache");
        (await database.ScalarAsync("SELECT \"Epoch\" FROM \"PermissionEpoch\" WHERE \"TenantId\" = 'tenant-b'")).ShouldBe(epochOfBBefore);
        (await database.ScalarAsync("SELECT \"Epoch\" FROM \"PermissionEpoch\" WHERE \"TenantId\" = 'tenant-a'")).ShouldBe(epochOfBBefore + 1, "only the editing tenant's epoch moved");
    }

    [Fact]
    public async Task A_raw_edit_that_does_not_move_the_epoch_stays_invisible_to_a_warm_instance_until_it_does_which_is_why_epoch_bumps_are_the_contract()
    {
        using var database = SharedSqliteDatabase.CreateFile();
        using var instanceB = ApiFactory.With(new ApiFactoryOptions { Database = database });
        using var staffOnB = await instanceB.ClientForAsync(SeedIds.CorporateStaffA);
        (await staffOnB.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.OK);

        await database.ExecuteAsync("DELETE FROM \"RolePermission\" WHERE \"RoleKey\" = 'corporate-staff' AND \"PermissionKey\" = 'bookings.read'");

        (await staffOnB.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.OK, "warm cache, no epoch bump: the stale grant is still served");

        await database.ExecuteAsync("INSERT INTO \"PermissionEpoch\" (\"TenantId\", \"Epoch\") VALUES ('tenant-a', 1) ON CONFLICT (\"TenantId\") DO UPDATE SET \"Epoch\" = \"Epoch\" + 1");

        (await staffOnB.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task With_caching_turned_off_every_request_reads_permissions_from_the_database()
    {
        using var factory = ApiFactory.With(new ApiFactoryOptions
        {
            Settings = new Dictionary<string, string?> { ["Persistence:CachePermissions"] = "false" },
        });
        using var staff = await factory.ClientForAsync(SeedIds.CorporateStaffA);
        (await staff.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.OK);

        await factory.ExecuteSqliteAsync("DELETE FROM \"RolePermission\" WHERE \"RoleKey\" = 'corporate-staff' AND \"PermissionKey\" = 'bookings.read'");

        (await staff.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        Stats(factory).EpochReads.ShouldBe(0);
    }
}
