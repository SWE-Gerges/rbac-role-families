using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Rbac.Abstractions;
using Rbac.Demo.Contracts;
using Rbac.Core.Validation;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

/// <summary>State that must survive a restart: token versions and the stored role catalog.</summary>
[Trait("Category", "Integration")]
public class PersistedStateTests
{
    [Fact]
    public async Task A_token_version_bump_survives_a_restart()
    {
        using var first = new ApiFactory();
        var staleToken = await first.TokenForAsync(SeedIds.InternalAdminB);
        await first.Services.GetRequiredService<ITokenVersionStore>().BumpAsync(SeedIds.TenantB, SeedIds.InternalAdminB, CancellationToken.None);

        // A restart: a new host with new singletons over the same database.
        using var restarted = first.WithWebHostBuilder(_ => { });
        using var client = restarted.CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", staleToken);

        (await client.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task The_runtime_reads_the_stored_role_catalog_not_the_code_definition()
    {
        using var first = new ApiFactory();
        using (var _ = first.CreateClient())
        {
        }

        using (var before = await first.ClientForAsync(SeedIds.AgencyStaffA))
        {
            (await ApiHelpers.ListIdsAsync(before)).Ids.Count.ShouldBe(4);
        }

        // An operator moves agency-staff into the internal family in the Role table, then the service restarts.
        await first.ExecuteSqliteAsync("UPDATE \"Role\" SET \"Family\" = 'Internal' WHERE \"Key\" = 'agency-staff'");
        using var restarted = first.WithWebHostBuilder(_ => { });
        using var client = restarted.CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", await first.TokenForAsync(SeedIds.AgencyStaffA));

        var (status, ids) = await ApiHelpers.ListIdsAsync(client);

        status.ShouldBe(HttpStatusCode.OK);
        ids.Count.ShouldBe(13, "agency-staff now resolves to the internal strategy: internal-written and guest bookings");
    }

    [Fact]
    public async Task A_stored_role_with_an_undefined_family_stops_the_host()
    {
        using var first = new ApiFactory();
        using (var _ = first.CreateClient())
        {
        }

        await first.ExecuteSqliteAsync("UPDATE \"Role\" SET \"Family\" = 'Galaxy' WHERE \"Key\" = 'agency-staff'");
        using var restarted = first.WithWebHostBuilder(_ => { });

        var exception = await Should.ThrowAsync<Exception>(() => Task.Run(() => restarted.CreateClient().Dispose()));

        var failure = Unwrap(exception);
        failure.Problems.ShouldContain(p => p.Contains("'agency-staff'") && p.Contains("no valid role family"));
    }

    [Fact]
    public async Task A_restart_runs_the_seeder_again_without_undoing_an_administrators_role_edit_or_moving_the_epoch()
    {
        using var database = SharedSqliteDatabase.CreateFile();
        long epochAfterEdit;
        using (var first = ApiFactory.With(new ApiFactoryOptions { Database = database }))
        {
            using var system = await first.ClientForAsync(SeedIds.SystemAdminA);
            var role = await (await system.GetAsync("/api/v1/roles/agency-staff")).ReadAsAsync<RoleResponse>();
            (await system.PutAsJsonAsync(
                "/api/v1/roles/agency-staff/permissions",
                new SetRolePermissionsRequest([.. role.Permissions.Where(p => p != "bookings.cancel")]),
                ApiFactory.Json)).StatusCode.ShouldBe(HttpStatusCode.OK);
            epochAfterEdit = await database.ScalarAsync("SELECT \"Epoch\" FROM \"PermissionEpoch\" WHERE \"TenantId\" = 'tenant-a'");
        }

        using var second = ApiFactory.With(new ApiFactoryOptions { Database = database });
        using var client = await second.ClientForAsync(SeedIds.SystemAdminA);

        var after = await (await client.GetAsync("/api/v1/roles/agency-staff")).ReadAsAsync<RoleResponse>();
        after.Permissions.ShouldNotContain("bookings.cancel");
        (await database.ScalarAsync("SELECT \"Epoch\" FROM \"PermissionEpoch\" WHERE \"TenantId\" = 'tenant-a'")).ShouldBe(epochAfterEdit, "a start that changes nothing moves no epoch");
        (await database.ScalarAsync("SELECT COUNT(*) FROM \"RoleDefaultSeed\" WHERE \"TenantId\" = 'tenant-a' AND \"RoleKey\" = 'agency-staff' AND \"PermissionKey\" = 'bookings.cancel'")).ShouldBe(1, "the pair stays recorded as handed out");
    }

    private static RbacConfigurationException Unwrap(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException!)
        {
            if (current is RbacConfigurationException configuration)
            {
                return configuration;
            }

            if (current.InnerException is null)
            {
                break;
            }
        }

        throw new InvalidOperationException("Not an RbacConfigurationException: " + exception);
    }
}
