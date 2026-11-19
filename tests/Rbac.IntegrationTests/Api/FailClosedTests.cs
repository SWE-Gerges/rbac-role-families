using System.Net;
using System.Net.Http.Json;
using Rbac.Abstractions;
using Rbac.Core.Catalog;
using Rbac.Demo.Contracts;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

[Trait("Category", "Integration")]
public class FailClosedTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    [Theory]
    [InlineData("not-a-role")]
    [InlineData("SYSTEM-ADMIN")]
    [InlineData("customer")]
    [InlineData("admin")]
    public async Task A_valid_token_with_an_unknown_role_is_anonymous_and_gets_nothing(string role)
    {
        using var client = factory.ClientWithToken(ForgedTokens.Staff(SeedIds.SystemAdminA, SeedIds.TenantA, role));

        var me = await (await client.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>();

        me.Kind.ShouldBe(PrincipalKind.Anonymous);
        me.Permissions.ShouldBeEmpty();
        (await client.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await client.GetAsync("/api/v1/bookings/bk-a-001")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await client.GetAsync("/api/v1/access-matrix")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task A_token_without_a_role_claim_is_never_treated_as_a_customer_or_any_default_role()
    {
        using var client = factory.ClientWithToken(ForgedTokens.Staff(SeedIds.CustomerA, SeedIds.TenantA, role: null));

        var me = await (await client.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>();

        me.Kind.ShouldBe(PrincipalKind.Anonymous);
        (await client.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task A_token_without_a_tenant_claim_is_rejected_before_any_permission_check()
    {
        var token = ForgedTokens.Create(
        [
            new System.Security.Claims.Claim("sub", SeedIds.SystemAdminA),
            new System.Security.Claims.Claim("role", RoleKeys.SystemAdmin),
            new System.Security.Claims.Claim("token_version", "1"),
        ]);
        using var client = factory.ClientWithToken(token);

        (await client.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        (await client.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_customer_token_that_also_carries_an_admin_role_claim_is_only_a_customer()
    {
        using var client = factory.ClientWithToken(
            ForgedTokens.Staff(SeedIds.CustomerA, SeedIds.TenantA, RoleKeys.SystemAdmin, kind: "customer"));

        var me = await (await client.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>();
        var (_, ids) = await ApiHelpers.ListIdsAsync(client);

        me.Kind.ShouldBe(PrincipalKind.Customer);
        me.RoleKey.ShouldBeNull();
        ids.Count.ShouldBe(4, "a customer sees their own bookings only");
        (await client.GetAsync("/api/v1/access-matrix")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Agency_staff_without_an_agency_pass_the_permission_gate_but_see_no_rows()
    {
        using var client = factory.ClientWithToken(ForgedTokens.Staff(SeedIds.AgencyStaffViewAllA, SeedIds.TenantA, RoleKeys.AgencyStaff));

        var (status, ids) = await ApiHelpers.ListIdsAsync(client);

        status.ShouldBe(HttpStatusCode.OK);
        ids.ShouldBeEmpty("the view-all grant must not widen a scope that has no agency");
        (await client.GetAsync("/api/v1/bookings/bk-a-026")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task An_agency_admin_without_an_agency_sees_nothing_and_corporate_roles_without_an_account_see_nothing()
    {
        foreach (var (user, role) in new[] { (SeedIds.AgencyAdminA, RoleKeys.AgencyAdmin), (SeedIds.CorporateAdminA, RoleKeys.CorporateAdmin), (SeedIds.CorporateStaffViewAllA, RoleKeys.CorporateStaff) })
        {
            using var client = factory.ClientWithToken(ForgedTokens.Staff(user, SeedIds.TenantA, role));

            var (status, ids) = await ApiHelpers.ListIdsAsync(client);

            status.ShouldBe(HttpStatusCode.OK, user);
            ids.ShouldBeEmpty(user);
        }
    }

    [Fact]
    public async Task A_role_that_is_not_listed_for_a_gated_endpoint_is_forbidden_not_allowed_by_omission()
    {
        foreach (var user in new[] { SeedIds.ReportViewerA, SeedIds.InternalStaffA, SeedIds.AgencyStaffA, SeedIds.CustomerA, SeedIds.FinanceOfficerA })
        {
            using var client = await factory.ClientForAsync(user);

            (await client.GetAsync("/api/v1/access-matrix")).StatusCode.ShouldBe(HttpStatusCode.Forbidden, user);
        }
    }

    [Fact]
    public async Task The_report_viewer_family_never_receives_booking_rows()
    {
        using var client = await factory.ClientForAsync(SeedIds.ReportViewerA);

        (await client.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await client.GetAsync("/api/v1/bookings/bk-a-001")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await client.PostAsync("/api/v1/bookings/bk-a-001/cancel", null)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await client.PostAsJsonAsync("/api/v1/bookings", new { type = "Hotel", amount = 1 }, ApiFactory.Json)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task A_token_for_a_user_that_does_not_exist_resolves_to_no_permissions()
    {
        using var client = factory.ClientWithToken(ForgedTokens.Staff("ghost", SeedIds.TenantA, RoleKeys.SystemAdmin));

        (await client.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await (await client.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>()).Permissions.ShouldBeEmpty();
    }

    [Fact]
    public async Task A_token_whose_role_does_not_match_the_stored_role_resolves_to_no_permissions()
    {
        using var client = factory.ClientWithToken(
            ForgedTokens.Staff(SeedIds.AgencyStaffA, SeedIds.TenantA, RoleKeys.SystemAdmin, SeedIds.AgencyA1));

        (await client.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }
}
