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
/// Soft delete and account-reuse hygiene: a deleted user disappears everywhere and cannot sign in, and a person who comes
/// back under the same handle is a new user with a new id that inherits nothing. Every test owns its factory.
/// </summary>
[Trait("Category", "Integration")]
public class AccountReuseApiTests
{
    private static async Task<DevTokenResponse> IssueAsync(ApiFactory factory, string userIdOrHandle)
    {
        using var client = factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/v1/dev/token", new DevTokenRequest(userIdOrHandle), ApiFactory.Json);
        response.EnsureSuccessStatusCode();
        return await response.ReadAsAsync<DevTokenResponse>();
    }

    [Fact]
    public async Task Delete_then_recreate_gives_a_new_id_that_inherits_no_overrides_bookings_or_sessions()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var agencyAdmin = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        using var oldSession = await factory.ClientForAsync(SeedIds.AgencyStaffViewAllA);
        var (_, oldVisible) = await ApiHelpers.ListIdsAsync(oldSession);
        oldVisible.Count.ShouldBeGreaterThan(3, "the seeded per-user grant widens this user's list");
        var oldOwn = await (await oldSession.GetAsync("/api/v1/bookings?pageSize=100")).ReadAsAsync<BookingListResponse>();
        var ownedByOld = oldOwn.Items.Where(b => b.OwnerUserId == SeedIds.AgencyStaffViewAllA).Select(b => b.Id).ToArray();
        ownedByOld.ShouldNotBeEmpty();

        (await system.DeleteAsync($"/api/v1/users/{SeedIds.AgencyStaffViewAllA}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var recreated = await ApiHelpers.CreateUserAsync(system, SeedIds.AgencyStaffViewAllA, RoleKeys.AgencyStaff, SeedIds.AgencyA1);

        recreated.Id.ShouldNotBe(SeedIds.AgencyStaffViewAllA);
        recreated.Handle.ShouldBe(SeedIds.AgencyStaffViewAllA);
        recreated.PermissionsVersion.ShouldBe(1);
        (await oldSession.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "the old session stays dead");

        // Signing in by the handle now reaches the new user; the old id is gone.
        var token = await IssueAsync(factory, SeedIds.AgencyStaffViewAllA);
        token.UserId.ShouldBe(recreated.Id);

        using var newSession = factory.ClientWithToken(token.AccessToken);
        var me = await (await newSession.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>();
        me.UserId.ShouldBe(recreated.Id);
        me.Permissions.ShouldNotContain(Permissions.BookingsViewAllAgency, "the old per-user grant stayed with the old id");
        var (_, newVisible) = await ApiHelpers.ListIdsAsync(newSession);
        newVisible.ShouldBeEmpty("an agency staff member sees only their own bookings, and the new user owns none");
        foreach (var id in ownedByOld)
        {
            (await newSession.GetAsync($"/api/v1/bookings/{id}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        }

        // History is retained, not reassigned: the bookings still belong to the old id and the agency admin still sees them.
        foreach (var id in ownedByOld)
        {
            var booking = await (await agencyAdmin.GetAsync($"/api/v1/bookings/{id}")).ReadAsAsync<BookingResponse>();
            booking.OwnerUserId.ShouldBe(SeedIds.AgencyStaffViewAllA);
        }

        (await factory.ScalarSqliteAsync($"SELECT COUNT(*) FROM \"UserPermission\" WHERE \"UserId\" = '{recreated.Id}'")).ShouldBe(0);
        (await factory.ScalarSqliteAsync($"SELECT COUNT(*) FROM \"User\" WHERE \"Handle\" = '{SeedIds.AgencyStaffViewAllA}'")).ShouldBe(2, "the deleted row is kept next to the new one");
    }

    [Fact]
    public async Task A_returning_person_gets_only_the_role_they_are_given_now()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        (await system.DeleteAsync($"/api/v1/users/{SeedIds.AgencyAdmin2A}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var returned = await ApiHelpers.CreateUserAsync(system, SeedIds.AgencyAdmin2A, RoleKeys.CorporateStaff, corporateId: SeedIds.CorporateA1);

        returned.RoleKey.ShouldBe(RoleKeys.CorporateStaff);
        returned.AgencyId.ShouldBeNull("no account is carried over");
        returned.IsFoundingAdmin.ShouldBeFalse();
        using var session = await factory.ClientForAsync(returned.Handle, freshToken: true);
        var me = await (await session.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>();
        me.RoleKey.ShouldBe(RoleKeys.CorporateStaff);
        me.Permissions.ShouldNotContain(Permissions.UsersManage);
    }

    [Fact]
    public async Task A_replaced_founding_admin_is_a_new_user_and_becomes_the_new_founder()
    {
        using var factory = new ApiFactory();
        using var internalAdmin = await factory.ClientForAsync(SeedIds.InternalAdminA);
        (await internalAdmin.DeleteAsync($"/api/v1/users/{SeedIds.Agency2AdminA}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var replacement = await ApiHelpers.CreateUserAsync(internalAdmin, SeedIds.Agency2AdminA, RoleKeys.AgencyAdmin, SeedIds.AgencyA2);

        replacement.Id.ShouldNotBe(SeedIds.Agency2AdminA);
        replacement.IsFoundingAdmin.ShouldBeTrue();
        (await factory.ScalarSqliteAsync($"SELECT COUNT(*) FROM \"User\" WHERE \"AgencyId\" = '{SeedIds.AgencyA2}' AND \"IsFoundingAdmin\" = 1 AND \"DeletedAt\" IS NULL")).ShouldBe(1);
    }

    [Fact]
    public async Task A_live_handle_cannot_be_taken_but_a_deleted_one_can_and_each_user_keeps_a_separate_audit_trail()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);

        var first = await ApiHelpers.CreateUserAsync(system, "recurring-person", RoleKeys.InternalStaff);
        (await system.PostAsJsonAsync("/api/v1/users", new CreateUserRequest("recurring-person", "Again", RoleKeys.InternalStaff), ApiFactory.Json))
            .StatusCode.ShouldBe(HttpStatusCode.Conflict);
        (await system.DeleteAsync($"/api/v1/users/{first.Id}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        var second = await ApiHelpers.CreateUserAsync(system, "recurring-person", RoleKeys.InternalStaff);

        second.Id.ShouldNotBe(first.Id);
        var trail = await (await system.GetAsync("/api/v1/audit?pageSize=100")).ReadAsAsync<AuditListResponse>();
        trail.Items.Where(e => e.TargetId == first.Id).Select(e => e.Action).Order().ShouldBe(["user.created", "user.deleted"]);
        trail.Items.Where(e => e.TargetId == second.Id).Select(e => e.Action).ShouldBe(["user.created"]);
    }

    [Fact]
    public async Task A_deleted_user_cannot_be_read_edited_deleted_again_or_acted_as_and_a_stolen_token_is_dead()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var stolen = await factory.ClientForAsync(SeedIds.CorporateStaffViewAllA);
        (await system.DeleteAsync($"/api/v1/users/{SeedIds.CorporateStaffViewAllA}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var id = SeedIds.CorporateStaffViewAllA;
        (await system.GetAsync($"/api/v1/users/{id}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await system.GetAsync($"/api/v1/users/{id}/permissions")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await system.DeleteAsync($"/api/v1/users/{id}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await system.PutAsJsonAsync($"/api/v1/users/{id}/role", new ChangeRoleRequest(RoleKeys.CorporateAdmin, null, SeedIds.CorporateA1), ApiFactory.Json)).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        using var actAs = new HttpRequestMessage(HttpMethod.Get, "/api/v1/me");
        actAs.Headers.Add("X-On-Behalf-Of", id);
        (await system.SendAsync(actAs)).StatusCode.ShouldBe(HttpStatusCode.NotFound);

        (await stolen.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        var (_, listed) = await ApiHelpers.ListUserIdsAsync(system);
        listed.ShouldNotContain(id);
        (await factory.ScalarSqliteAsync($"SELECT COUNT(*) FROM \"AuditEntry\" WHERE \"TargetId\" = '{id}'")).ShouldBe(1, "only the delete itself is audited");
    }

    [Fact]
    public async Task A_deleted_customer_is_gone_the_same_way()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var customer = await factory.ClientForAsync(SeedIds.CustomerA);

        (await system.DeleteAsync($"/api/v1/users/{SeedIds.CustomerA}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        (await customer.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        (await system.GetAsync($"/api/v1/users/{SeedIds.CustomerA}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        using var fresh = factory.CreateClient();
        (await fresh.PostAsJsonAsync("/api/v1/dev/token", new DevTokenRequest(SeedIds.CustomerA), ApiFactory.Json)).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        var persisted = await factory.ScalarSqliteAsync($"SELECT COUNT(*) FROM \"Booking\" WHERE \"OwnerUserId\" = '{SeedIds.CustomerA}'");
        persisted.ShouldBeGreaterThan(0, "the customer's bookings are history, not deleted");
    }
}
