using System.Net;
using System.Net.Http.Json;
using Rbac.Core.Catalog;
using Rbac.Demo.Contracts;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

/// <summary>
/// Role changes, soft deletes and the founding-admin rule over HTTP. Every test owns its factory: these writes bump token
/// versions, so a shared fixture would make later tests fail on a revoked cached token depending on test order.
/// </summary>
[Trait("Category", "Integration")]
public class UserManagementApiTests
{
    private static Task<HttpResponseMessage> ChangeRoleAsync(HttpClient client, string userId, string roleKey, string? agencyId = null, string? corporateId = null) =>
        client.PutAsJsonAsync($"/api/v1/users/{userId}/role", new ChangeRoleRequest(roleKey, agencyId, corporateId), ApiFactory.Json);

    private static async Task<UserResponse> GetUserAsync(HttpClient client, string userId) =>
        await (await client.GetAsync($"/api/v1/users/{userId}")).ReadAsAsync<UserResponse>();

    [Fact]
    public async Task A_role_change_takes_effect_on_the_next_request_and_revokes_the_users_old_sessions()
    {
        using var factory = new ApiFactory();
        using var founder = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        using var staffBefore = await factory.ClientForAsync(SeedIds.AgencyStaffA);
        var (_, ownBefore) = await ApiHelpers.ListIdsAsync(staffBefore);

        var response = await ChangeRoleAsync(founder, SeedIds.AgencyStaffA, RoleKeys.AgencyAdmin, SeedIds.AgencyA1);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var changed = await response.ReadAsAsync<UserResponse>();
        changed.RoleKey.ShouldBe(RoleKeys.AgencyAdmin);
        changed.IsFoundingAdmin.ShouldBeFalse("the account already has a founding admin");
        changed.PermissionsVersion.ShouldBe(2);

        (await staffBefore.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        using var staffAfter = await factory.ClientForAsync(SeedIds.AgencyStaffA, freshToken: true);
        (await (await staffAfter.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>()).RoleKey.ShouldBe(RoleKeys.AgencyAdmin);
        var (_, ownAfter) = await ApiHelpers.ListIdsAsync(staffAfter);
        ownAfter.Count.ShouldBeGreaterThan(ownBefore.Count, "an agency admin sees the whole agency");
        ownBefore.ShouldBeSubsetOf(ownAfter);
    }

    [Fact]
    public async Task A_historical_booking_keeps_the_family_it_was_stamped_with_when_its_owner_changes_role()
    {
        using var factory = new ApiFactory();
        using var internalAdmin = await factory.ClientForAsync(SeedIds.InternalAdminA);
        using var staff = await factory.ClientForAsync(SeedIds.InternalStaffA);
        var booking = await ApiHelpers.CreateBookingAsync(staff);

        (await ChangeRoleAsync(internalAdmin, SeedIds.InternalStaffA, RoleKeys.AgencyStaff, SeedIds.AgencyA1)).StatusCode.ShouldBe(HttpStatusCode.OK);

        using var agencyAdmin = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        (await agencyAdmin.GetAsync($"/api/v1/bookings/{booking.Id}")).StatusCode.ShouldBe(HttpStatusCode.NotFound, "the booking stays an internal booking");
        (await internalAdmin.GetAsync($"/api/v1/bookings/{booking.Id}")).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_plain_admin_cannot_promote_delete_or_demote_and_nobody_in_the_account_touches_the_founding_admin()
    {
        using var factory = new ApiFactory();
        using var plainAdmin = await factory.ClientForAsync(SeedIds.AgencyAdmin2A);
        using var founder = await factory.ClientForAsync(SeedIds.AgencyAdminA);

        (await ChangeRoleAsync(plainAdmin, SeedIds.AgencyStaffA, RoleKeys.AgencyAdmin, SeedIds.AgencyA1)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await ChangeRoleAsync(plainAdmin, SeedIds.AgencyAdminA, RoleKeys.AgencyStaff, SeedIds.AgencyA1)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await plainAdmin.DeleteAsync($"/api/v1/users/{SeedIds.AgencyAdminA}")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        (await founder.DeleteAsync($"/api/v1/users/{SeedIds.AgencyAdminA}")).StatusCode.ShouldBe(HttpStatusCode.Forbidden, "not even by themselves");
        (await ChangeRoleAsync(founder, SeedIds.AgencyAdminA, RoleKeys.AgencyStaff, SeedIds.AgencyA1)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        var stillFounder = await GetUserAsync(founder, SeedIds.AgencyAdminA);
        stillFounder.IsFoundingAdmin.ShouldBeTrue();
        stillFounder.RoleKey.ShouldBe(RoleKeys.AgencyAdmin);
    }

    [Fact]
    public async Task The_founding_admin_manages_the_other_admins_of_their_account()
    {
        using var factory = new ApiFactory();
        using var founder = await factory.ClientForAsync(SeedIds.AgencyAdminA);

        (await ChangeRoleAsync(founder, SeedIds.AgencyAdmin2A, RoleKeys.AgencyStaff, SeedIds.AgencyA1)).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await founder.DeleteAsync($"/api/v1/users/{SeedIds.AgencyStaffA}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task An_internal_admin_can_remove_a_founding_admin_and_the_next_admin_of_that_account_becomes_the_founder()
    {
        using var factory = new ApiFactory();
        using var internalAdmin = await factory.ClientForAsync(SeedIds.InternalAdminA);
        using var oldFounderSession = await factory.ClientForAsync(SeedIds.AgencyAdminA);

        (await internalAdmin.DeleteAsync($"/api/v1/users/{SeedIds.AgencyAdminA}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        (await oldFounderSession.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        (await internalAdmin.GetAsync($"/api/v1/users/{SeedIds.AgencyAdminA}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);

        var next = await ApiHelpers.CreateUserAsync(internalAdmin, "next-founder", RoleKeys.AgencyAdmin, agencyId: SeedIds.AgencyA1);
        next.IsFoundingAdmin.ShouldBeTrue();
        var another = await ApiHelpers.CreateUserAsync(internalAdmin, "another-admin", RoleKeys.AgencyAdmin, agencyId: SeedIds.AgencyA1);
        another.IsFoundingAdmin.ShouldBeFalse("an account has one founding admin");
    }

    [Fact]
    public async Task The_first_admin_of_a_new_account_is_its_founding_admin_and_a_demotion_clears_the_flag()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);

        var first = await ApiHelpers.CreateUserAsync(system, "fresh-corp-admin", RoleKeys.CorporateAdmin, corporateId: "corp-new");
        var second = await ApiHelpers.CreateUserAsync(system, "fresh-corp-admin-2", RoleKeys.CorporateAdmin, corporateId: "corp-new");

        first.IsFoundingAdmin.ShouldBeTrue();
        second.IsFoundingAdmin.ShouldBeFalse();

        var demoted = await (await ChangeRoleAsync(system, first.Id, RoleKeys.CorporateStaff, corporateId: "corp-new")).ReadAsAsync<UserResponse>();
        demoted.IsFoundingAdmin.ShouldBeFalse();
    }

    [Fact]
    public async Task Delete_is_soft_the_user_vanishes_from_every_read_and_cannot_sign_in_again()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var victimSession = await factory.ClientForAsync(SeedIds.CorporateStaffA);

        (await system.DeleteAsync($"/api/v1/users/{SeedIds.CorporateStaffA}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        (await victimSession.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        (await system.GetAsync($"/api/v1/users/{SeedIds.CorporateStaffA}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        var (_, listed) = await ApiHelpers.ListUserIdsAsync(system);
        listed.ShouldNotContain(SeedIds.CorporateStaffA);
        using var anonymous = factory.CreateClient();
        using var tokenRequest = await anonymous.PostAsJsonAsync("/api/v1/dev/token", new DevTokenRequest(SeedIds.CorporateStaffA), ApiFactory.Json);
        tokenRequest.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await factory.ScalarSqliteAsync($"SELECT COUNT(*) FROM \"User\" WHERE \"Id\" = '{SeedIds.CorporateStaffA}' AND \"DeletedAt\" IS NOT NULL")).ShouldBe(1, "the row is kept");
    }

    [Fact]
    public async Task Role_change_and_delete_are_refused_across_tenants_and_leave_the_target_untouched()
    {
        using var factory = new ApiFactory();
        using var foreign = await factory.ClientForAsync(SeedIds.SystemAdminB);
        using var home = await factory.ClientForAsync(SeedIds.SystemAdminA);

        (await ChangeRoleAsync(foreign, SeedIds.AgencyStaffA, RoleKeys.AgencyAdmin, SeedIds.AgencyA1)).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await foreign.DeleteAsync($"/api/v1/users/{SeedIds.AgencyStaffA}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);

        var untouched = await GetUserAsync(home, SeedIds.AgencyStaffA);
        untouched.RoleKey.ShouldBe(RoleKeys.AgencyStaff);
        untouched.PermissionsVersion.ShouldBe(1);
    }

    [Fact]
    public async Task A_created_user_always_belongs_to_the_callers_tenant_and_is_invisible_to_other_tenants()
    {
        using var factory = new ApiFactory();
        using var tenantB = await factory.ClientForAsync(SeedIds.SystemAdminB);
        using var tenantA = await factory.ClientForAsync(SeedIds.SystemAdminA);

        var created = await ApiHelpers.CreateUserAsync(tenantB, "tenant-b-newcomer", RoleKeys.InternalStaff);

        created.TenantId.ShouldBe(SeedIds.TenantB);
        (await tenantA.GetAsync($"/api/v1/users/{created.Id}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await tenantB.GetAsync($"/api/v1/users/{created.Id}")).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Refusals_follow_the_documented_status_and_are_problem_documents()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var agencyAdmin = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        using var agencyStaff = await factory.ClientForAsync(SeedIds.AgencyStaffA);
        using var anonymous = factory.CreateClient();

        var cases = new (string Label, Func<Task<HttpResponseMessage>> Call, HttpStatusCode Expected)[]
        {
            ("unknown role", () => ChangeRoleAsync(system, SeedIds.InternalStaffA, "no-such-role"), HttpStatusCode.BadRequest),
            ("customers have no role", () => ChangeRoleAsync(system, SeedIds.CustomerA, RoleKeys.InternalStaff), HttpStatusCode.BadRequest),
            ("agency role without an account", () => ChangeRoleAsync(system, SeedIds.InternalStaffA, RoleKeys.AgencyStaff), HttpStatusCode.BadRequest),
            ("a role outside the callers creation graph", () => ChangeRoleAsync(agencyAdmin, SeedIds.AgencyStaffA, RoleKeys.InternalStaff), HttpStatusCode.Forbidden),
            ("deleting yourself", () => system.DeleteAsync($"/api/v1/users/{SeedIds.SystemAdminA}"), HttpStatusCode.Forbidden),
            ("an agency admin deleting a peer in another account", () => agencyAdmin.DeleteAsync($"/api/v1/users/{SeedIds.Agency2AdminA}"), HttpStatusCode.NotFound),
            ("missing user", () => system.DeleteAsync("/api/v1/users/usr-nobody"), HttpStatusCode.NotFound),
            ("no users.manage permission", () => agencyStaff.DeleteAsync($"/api/v1/users/{SeedIds.AgencyStaffViewAllA}"), HttpStatusCode.Forbidden),
            ("no users.manage permission on role change", () => ChangeRoleAsync(agencyStaff, SeedIds.AgencyStaffViewAllA, RoleKeys.AgencyAdmin, SeedIds.AgencyA1), HttpStatusCode.Forbidden),
            ("not authenticated", () => anonymous.DeleteAsync($"/api/v1/users/{SeedIds.AgencyStaffA}"), HttpStatusCode.Unauthorized),
        };

        var failures = new List<string>();
        foreach (var (label, call, expected) in cases)
        {
            using var response = await call();
            if (response.StatusCode != expected)
            {
                failures.Add($"{label}: expected {(int)expected} but got {(int)response.StatusCode}");
            }
            else if (!MatrixRunner.IsProblem(response))
            {
                failures.Add($"{label}: the refusal is not a problem document");
            }
        }

        failures.ShouldBeEmpty(string.Join(Environment.NewLine, failures));
    }

    [Fact]
    public async Task Creating_a_user_with_a_taken_handle_is_a_409_and_a_bad_handle_is_a_400()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);

        (await system.PostAsJsonAsync("/api/v1/users", new CreateUserRequest(SeedIds.InternalStaffA, "Duplicate", RoleKeys.InternalStaff), ApiFactory.Json))
            .StatusCode.ShouldBe(HttpStatusCode.Conflict);
        (await system.PostAsJsonAsync("/api/v1/users", new CreateUserRequest("Not A Handle!", "Bad", RoleKeys.InternalStaff), ApiFactory.Json))
            .StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await system.PostAsJsonAsync("/api/v1/users", new CreateUserRequest("fine-handle", "  ", RoleKeys.InternalStaff), ApiFactory.Json))
            .StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }
}
