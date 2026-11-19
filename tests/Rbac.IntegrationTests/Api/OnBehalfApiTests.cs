using System.Net;
using System.Net.Http.Json;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;
using Rbac.Demo.Contracts;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

/// <summary>
/// X-On-Behalf-Of: the effective user's scope and permissions apply, the actor must be allowed to act as them, and both ids reach
/// the audit trail. Every test owns its factory.
/// </summary>
[Trait("Category", "Integration")]
public class OnBehalfApiTests
{
    private const string Header = "X-On-Behalf-Of";

    private static HttpRequestMessage Get(string path, string? onBehalfOf)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (onBehalfOf is not null)
        {
            request.Headers.TryAddWithoutValidation(Header, onBehalfOf);
        }

        return request;
    }

    private static async Task<HttpStatusCode> StatusAsync(HttpClient client, string path, string? onBehalfOf)
    {
        using var request = Get(path, onBehalfOf);
        using var response = await client.SendAsync(request);
        return response.StatusCode;
    }

    private static async Task<IReadOnlyList<string>> BookingIdsAsync(HttpClient client, string? onBehalfOf)
    {
        var ids = new List<string>();
        for (var page = 1; ; page++)
        {
            using var request = Get($"/api/v1/bookings?pageSize=100&page={page}", onBehalfOf);
            using var response = await client.SendAsync(request);
            response.StatusCode.ShouldBe(HttpStatusCode.OK);
            var body = await response.ReadAsAsync<BookingListResponse>();
            ids.AddRange(body.Items.Select(i => i.Id));
            if (ids.Count >= body.TotalCount || body.Items.Count == 0)
            {
                return ids;
            }
        }
    }

    [Fact]
    public async Task The_effective_users_scope_applies_not_the_actors()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var staff = await factory.ClientForAsync(SeedIds.AgencyStaffA);
        using var customer = await factory.ClientForAsync(SeedIds.CustomerA);

        var asSystem = await BookingIdsAsync(system, onBehalfOf: null);
        var asStaff = await BookingIdsAsync(system, SeedIds.AgencyStaffA);
        var asCustomer = await BookingIdsAsync(system, SeedIds.CustomerA);

        asSystem.Count.ShouldBe(48);
        asStaff.Order().ShouldBe((await ApiHelpers.ListIdsAsync(staff)).Ids.Order(), "exactly what the agency staff member sees");
        asStaff.Count.ShouldBeLessThan(asSystem.Count);
        asCustomer.Order().ShouldBe((await ApiHelpers.ListIdsAsync(customer)).Ids.Order());

        using var byId = Get("/api/v1/bookings/bk-a-001", SeedIds.AgencyStaffA);
        (await system.SendAsync(byId)).StatusCode.ShouldBe(HttpStatusCode.NotFound, "out of the effective user's scope, though inside the actor's");
    }

    [Fact]
    public async Task The_effective_users_permissions_apply_so_an_actor_cannot_use_their_own_through_the_header()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);

        (await StatusAsync(system, "/api/v1/users", onBehalfOf: null)).ShouldBe(HttpStatusCode.OK);
        (await StatusAsync(system, "/api/v1/users", SeedIds.AgencyStaffA)).ShouldBe(HttpStatusCode.Forbidden);
        (await StatusAsync(system, "/api/v1/audit", SeedIds.AgencyAdminA)).ShouldBe(HttpStatusCode.Forbidden);
        (await StatusAsync(system, "/api/v1/users", SeedIds.AgencyAdminA)).ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Me_shows_the_effective_user_and_who_is_acting()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);

        using var request = Get("/api/v1/me", SeedIds.AgencyStaffA);
        var me = await (await system.SendAsync(request)).ReadAsAsync<MeResponse>();
        var plain = await (await system.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>();

        me.UserId.ShouldBe(SeedIds.AgencyStaffA);
        me.ActingUserId.ShouldBe(SeedIds.SystemAdminA);
        me.RoleKey.ShouldBe(RoleKeys.AgencyStaff);
        me.AgencyId.ShouldBe(SeedIds.AgencyA1);
        me.Permissions.ShouldNotContain(Permissions.UsersActOnBehalf);
        plain.ActingUserId.ShouldBeNull();
        plain.UserId.ShouldBe(SeedIds.SystemAdminA);
    }

    [Fact]
    public async Task Without_the_permission_the_header_is_a_403_even_for_a_valid_target_and_never_silently_ignored()
    {
        using var factory = new ApiFactory();

        foreach (var caller in new[] { SeedIds.AgencyAdminA, SeedIds.CorporateAdminA, SeedIds.InternalStaffA, SeedIds.FinanceOfficerA, SeedIds.AgencyStaffA, SeedIds.ReportViewerA, SeedIds.CustomerA })
        {
            using var client = await factory.ClientForAsync(caller);
            using var valid = Get("/api/v1/me", SeedIds.AgencyStaffViewAllA);
            using var response = await client.SendAsync(valid);

            response.StatusCode.ShouldBe(HttpStatusCode.Forbidden, caller);
            MatrixRunner.IsProblem(response).ShouldBeTrue(caller);
            (await StatusAsync(client, "/api/v1/me", "usr-does-not-exist")).ShouldBe(HttpStatusCode.Forbidden, $"{caller}: the permission is checked before the target is looked up");
        }
    }

    [Fact]
    public async Task An_anonymous_request_with_the_header_is_a_401_and_the_header_does_not_disturb_anonymous_endpoints()
    {
        using var factory = new ApiFactory();
        using var anonymous = factory.CreateClient();

        (await StatusAsync(anonymous, "/api/v1/me", SeedIds.AgencyStaffA)).ShouldBe(HttpStatusCode.Unauthorized);
        (await StatusAsync(anonymous, "/health/live", SeedIds.AgencyStaffA)).ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Equal_or_higher_standing_other_tenants_and_unusable_targets_are_refused()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var internalAdmin = await factory.ClientForAsync(SeedIds.InternalAdminA);
        var peer = await ApiHelpers.CreateUserAsync(system, "second-internal-admin", RoleKeys.InternalAdmin);
        var doomed = await ApiHelpers.CreateUserAsync(system, "soon-deleted", RoleKeys.InternalStaff);
        var idle = await ApiHelpers.CreateUserAsync(system, "soon-inactive", RoleKeys.InternalStaff);
        (await system.DeleteAsync($"/api/v1/users/{doomed.Id}")).EnsureSuccessStatusCode();
        await factory.ExecuteSqliteAsync($"UPDATE \"User\" SET \"IsActive\" = 0 WHERE \"Id\" = '{idle.Id}'");

        var cases = new (string Label, HttpClient Client, string Target, HttpStatusCode Expected)[]
        {
            ("the actor themselves", system, SeedIds.SystemAdminA, HttpStatusCode.Forbidden),
            ("an internal admin acting as a peer", internalAdmin, peer.Id, HttpStatusCode.Forbidden),
            ("an internal admin acting as themselves", internalAdmin, SeedIds.InternalAdminA, HttpStatusCode.Forbidden),
            ("an internal admin acting as a system admin (not visible to them)", internalAdmin, SeedIds.SystemAdminA, HttpStatusCode.NotFound),
            ("a user of another tenant", system, SeedIds.AgencyStaffB, HttpStatusCode.NotFound),
            ("the system admin of another tenant", system, SeedIds.SystemAdminB, HttpStatusCode.NotFound),
            ("a user that does not exist", system, "usr-does-not-exist", HttpStatusCode.NotFound),
            ("a soft deleted user", system, doomed.Id, HttpStatusCode.NotFound),
            ("a deactivated user", system, idle.Id, HttpStatusCode.Forbidden),
        };

        var failures = new List<string>();
        foreach (var (label, client, target, expected) in cases)
        {
            using var request = Get("/api/v1/me", target);
            using var response = await client.SendAsync(request);
            if (response.StatusCode != expected)
            {
                failures.Add($"{label}: expected {(int)expected} but got {(int)response.StatusCode}");
            }
            else if (!MatrixRunner.IsProblem(response))
            {
                failures.Add($"{label}: not a problem document");
            }
        }

        failures.ShouldBeEmpty(string.Join(Environment.NewLine, failures));
        (await StatusAsync(internalAdmin, "/api/v1/me", SeedIds.InternalStaffA)).ShouldBe(HttpStatusCode.OK, "a lower role in their own family is fine");
    }

    [Fact]
    public async Task A_delegated_actor_inside_an_account_can_act_only_as_staff_of_that_account()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var adminOnly = await factory.ClientForAsync(SeedIds.AgencyAdmin2A);

        // The system admin holds the permission, so it can hand it to an agency admin (the grant ceiling allows it).
        using var read = await system.GetAsync($"/api/v1/users/{SeedIds.AgencyAdmin2A}/permissions");
        var version = (await read.ReadAsAsync<UserPermissionsResponse>()).Version;
        using var grant = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/users/{SeedIds.AgencyAdmin2A}/permissions")
        {
            Content = JsonContent.Create(new EditUserPermissionsRequest(Grant: [Permissions.UsersActOnBehalf]), options: ApiFactory.Json),
        };
        grant.Headers.TryAddWithoutValidation("If-Match", $"\"{version}\"");
        (await system.SendAsync(grant)).EnsureSuccessStatusCode();
        using var delegated = await factory.ClientForAsync(SeedIds.AgencyAdmin2A, freshToken: true);

        (await StatusAsync(delegated, "/api/v1/me", SeedIds.AgencyStaffA)).ShouldBe(HttpStatusCode.OK);
        (await StatusAsync(delegated, "/api/v1/me", SeedIds.AgencyAdminA)).ShouldBe(HttpStatusCode.Forbidden, "the founding admin of the account");
        (await StatusAsync(delegated, "/api/v1/me", SeedIds.Agency2AdminA)).ShouldBe(HttpStatusCode.NotFound, "another agency");
        (await StatusAsync(delegated, "/api/v1/me", SeedIds.CorporateStaffA)).ShouldBe(HttpStatusCode.NotFound, "another account kind");
        (await StatusAsync(delegated, "/api/v1/me", SeedIds.CustomerA)).ShouldBe(HttpStatusCode.NotFound, "customers are not visible to agency admins");
        (await StatusAsync(adminOnly, "/api/v1/me", SeedIds.AgencyStaffA)).ShouldBe(HttpStatusCode.Unauthorized, "the old session was revoked by the grant");
    }

    [Fact]
    public async Task Both_ids_are_written_to_the_audit_trail_and_the_effective_users_standing_decides_what_is_allowed()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);

        // As the founding agency admin, the system admin creates staff inside that admin's own account.
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/users")
        {
            Content = JsonContent.Create(new CreateUserRequest("created-on-behalf", "Created on behalf", RoleKeys.AgencyStaff, SeedIds.AgencyA1), options: ApiFactory.Json),
        };
        request.Headers.Add(Header, SeedIds.AgencyAdminA);
        request.Headers.Add("X-Correlation-Id", "on-behalf-1");
        var created = await system.SendAsync(request);
        created.StatusCode.ShouldBe(HttpStatusCode.Created);
        var user = await created.ReadAsAsync<UserResponse>();

        var entry = (await (await system.GetAsync($"/api/v1/audit?target={user.Id}")).ReadAsAsync<AuditListResponse>()).Items.Single();
        entry.ActorUserId.ShouldBe(SeedIds.SystemAdminA);
        entry.EffectiveUserId.ShouldBe(SeedIds.AgencyAdminA);
        entry.CorrelationId.ShouldBe("on-behalf-1");
        entry.Action.ShouldBe("user.created");

        // The effective user's rules apply: an agency admin cannot create an internal user, whoever asks.
        using var refused = new HttpRequestMessage(HttpMethod.Post, "/api/v1/users")
        {
            Content = JsonContent.Create(new CreateUserRequest("not-allowed", "Not allowed", RoleKeys.InternalStaff), options: ApiFactory.Json),
        };
        refused.Headers.Add(Header, SeedIds.AgencyAdminA);
        (await system.SendAsync(refused)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        // The same request without the header is the system admin acting for themselves and is not audited with an effective id.
        var own = await ApiHelpers.CreateUserAsync(system, "created-directly", RoleKeys.InternalStaff);
        (await (await system.GetAsync($"/api/v1/audit?target={own.Id}")).ReadAsAsync<AuditListResponse>()).Items.Single().EffectiveUserId.ShouldBeNull();
    }

    [Fact]
    public async Task Bookings_created_on_behalf_are_stamped_with_the_effective_user()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/bookings")
        {
            Content = JsonContent.Create(new CreateBookingRequest(BookingType.Hotel, 99m), options: ApiFactory.Json),
        };
        request.Headers.Add(Header, SeedIds.AgencyStaffA);

        var created = await (await system.SendAsync(request)).ReadAsAsync<BookingResponse>();

        created.OwnerUserId.ShouldBe(SeedIds.AgencyStaffA);
        created.AgencyId.ShouldBe(SeedIds.AgencyA1);
        created.OwnerRoleFamilyAtCreation.ShouldBe(Rbac.Abstractions.RoleFamily.Agency);
        using var staff = await factory.ClientForAsync(SeedIds.AgencyStaffA);
        (await staff.GetAsync($"/api/v1/bookings/{created.Id}")).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_malformed_or_repeated_header_is_a_400_and_the_channel_header_stays_non_authoritative()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);

        foreach (var bad in new[] { "a b", "<script>", new string('x', 65), $"{SeedIds.AgencyStaffA},{SeedIds.AgencyAdminA}" })
        {
            (await StatusAsync(system, "/api/v1/me", bad)).ShouldBe(HttpStatusCode.BadRequest, $"'{bad}'");
        }

        using var channel = Get("/api/v1/bookings?pageSize=100", onBehalfOf: null);
        channel.Headers.Add("X-Client-Channel", "web");
        using var withChannel = await system.SendAsync(channel);
        (await withChannel.ReadAsAsync<BookingListResponse>()).TotalCount.ShouldBe(48, "the channel hint grants nothing and takes nothing away");
        (await StatusAsync(system, "/api/v1/me", SeedIds.AgencyStaffA)).ShouldBe(HttpStatusCode.OK);
    }
}
