using System.Net;
using System.Net.Http.Json;
using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Demo.Contracts;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

[Trait("Category", "Integration")]
public class BookingsReadApiTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    [Fact]
    public async Task Listing_is_paged_newest_first_with_a_total_count()
    {
        using var client = await factory.ClientForAsync(SeedIds.SystemAdminA);

        var first = await (await client.GetAsync("/api/v1/bookings?pageSize=10")).ReadAsAsync<BookingListResponse>();
        var second = await (await client.GetAsync("/api/v1/bookings?pageSize=10&page=2")).ReadAsAsync<BookingListResponse>();

        first.Page.ShouldBe(1);
        first.PageSize.ShouldBe(10);
        first.TotalCount.ShouldBe(48);
        first.Items.Count.ShouldBe(10);
        first.Items.Select(i => i.CreatedAt).ShouldBe(first.Items.Select(i => i.CreatedAt).OrderDescending());
        second.Items.Select(i => i.Id).Intersect(first.Items.Select(i => i.Id)).ShouldBeEmpty();
        second.Items[0].CreatedAt.ShouldBeLessThanOrEqualTo(first.Items[^1].CreatedAt);
    }

    [Fact]
    public async Task The_default_page_size_is_20()
    {
        using var client = await factory.ClientForAsync(SeedIds.SystemAdminA);

        var page = await (await client.GetAsync("/api/v1/bookings")).ReadAsAsync<BookingListResponse>();

        page.PageSize.ShouldBe(20);
        page.Items.Count.ShouldBe(20);
    }

    [Fact]
    public async Task A_page_past_the_end_is_empty_but_still_reports_the_total()
    {
        using var client = await factory.ClientForAsync(SeedIds.AgencyStaffA);

        var page = await (await client.GetAsync("/api/v1/bookings?page=9")).ReadAsAsync<BookingListResponse>();

        page.Items.ShouldBeEmpty();
        page.TotalCount.ShouldBe(4);
    }

    [Theory]
    [InlineData("status=refunded")]
    [InlineData("status=REFUNDED")]
    [InlineData("status=Refunded")]
    public async Task The_status_filter_is_case_insensitive_and_only_returns_that_status(string query)
    {
        using var client = await factory.ClientForAsync(SeedIds.SystemAdminA);

        var page = await (await client.GetAsync($"/api/v1/bookings?{query}&pageSize=100")).ReadAsAsync<BookingListResponse>();

        page.Items.ShouldNotBeEmpty();
        page.Items.ShouldAllBe(i => i.Status == BookingStatus.Refunded);
    }

    [Theory]
    [InlineData("status=bogus")]
    [InlineData("status=3")]
    [InlineData("page=0")]
    [InlineData("page=-2")]
    [InlineData("pageSize=0")]
    [InlineData("pageSize=101")]
    public async Task Invalid_query_values_are_a_400_validation_problem(string query)
    {
        using var client = await factory.ClientForAsync(SeedIds.SystemAdminA);

        var response = await client.GetAsync($"/api/v1/bookings?{query}");

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        MatrixRunner.IsProblem(response).ShouldBeTrue();
        (await response.ReadJsonAsync()).GetProperty("errors").EnumerateObject().ShouldNotBeEmpty();
    }

    [Fact]
    public async Task Mine_narrows_the_list_to_the_callers_own_bookings_inside_their_scope()
    {
        using var client = await factory.ClientForAsync(SeedIds.AgencyAdminA);

        var all = await (await client.GetAsync("/api/v1/bookings?pageSize=100")).ReadAsAsync<BookingListResponse>();
        var mine = await (await client.GetAsync("/api/v1/bookings?mine=true&pageSize=100")).ReadAsAsync<BookingListResponse>();

        all.TotalCount.ShouldBe(13);
        mine.Items.ShouldNotBeEmpty();
        mine.Items.ShouldAllBe(i => i.OwnerUserId == SeedIds.AgencyAdminA);
        mine.Items.Select(i => i.Id).ShouldBeSubsetOf(all.Items.Select(i => i.Id));
    }

    [Fact]
    public async Task Mine_cannot_widen_the_scope_of_a_caller_who_owns_nothing_visible()
    {
        using var client = await factory.ClientForAsync(SeedIds.FinanceOfficerA);

        var mine = await (await client.GetAsync("/api/v1/bookings?mine=true")).ReadAsAsync<BookingListResponse>();

        mine.Items.ShouldAllBe(i => i.Status == BookingStatus.RefundRequested || i.Status == BookingStatus.Refunded);
    }

    [Fact]
    public async Task Get_by_id_returns_the_booking_inside_the_scope()
    {
        using var client = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        var listed = await (await client.GetAsync("/api/v1/bookings?pageSize=1")).ReadAsAsync<BookingListResponse>();
        var expected = listed.Items.Single();

        var response = await client.GetAsync($"/api/v1/bookings/{expected.Id}");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await response.ReadAsAsync<BookingResponse>()).ShouldBe(expected);
    }

    [Fact]
    public async Task An_out_of_scope_booking_and_a_missing_booking_are_indistinguishable()
    {
        using var client = await factory.ClientForAsync(SeedIds.AgencyStaffA);

        var outOfScope = await client.GetAsync("/api/v1/bookings/bk-a-001");
        var missing = await client.GetAsync("/api/v1/bookings/bk-does-not-exist");

        outOfScope.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        missing.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        var a = await outOfScope.ReadJsonAsync();
        var b = await missing.ReadJsonAsync();
        foreach (var name in new[] { "type", "title", "status", "detail" })
        {
            a.GetProperty(name).ToString().ShouldBe(b.GetProperty(name).ToString(), name);
        }
    }

    [Fact]
    public async Task The_me_endpoint_shows_the_principal_and_live_permissions()
    {
        using var client = await factory.ClientForAsync(SeedIds.AgencyStaffViewAllA);

        var me = await (await client.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>();

        me.Kind.ShouldBe(PrincipalKind.Staff);
        me.UserId.ShouldBe(SeedIds.AgencyStaffViewAllA);
        me.TenantId.ShouldBe(SeedIds.TenantA);
        me.RoleKey.ShouldBe("agency-staff");
        me.Family.ShouldBe(RoleFamily.Agency);
        me.AgencyId.ShouldBe(SeedIds.AgencyA1);
        me.Permissions.ShouldBe(["bookings.cancel", "bookings.create", "bookings.read", "bookings.view-all-agency"]);
    }

    [Fact]
    public async Task The_me_endpoint_shows_a_customer_as_a_customer_with_no_family()
    {
        using var client = await factory.ClientForAsync(SeedIds.CustomerA);

        var me = await (await client.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>();

        me.Kind.ShouldBe(PrincipalKind.Customer);
        me.RoleKey.ShouldBeNull();
        me.Family.ShouldBeNull();
        me.Permissions.ShouldBe(["bookings.cancel", "bookings.create", "bookings.read"]);
    }

    [Fact]
    public async Task The_access_matrix_is_computed_from_the_registry_and_lists_every_role_plus_customers_and_anonymous()
    {
        using var client = await factory.ClientForAsync(SeedIds.SystemAdminA);

        var matrix = await (await client.GetAsync("/api/v1/access-matrix")).ReadAsAsync<AccessMatrixResponse>();

        matrix.Rows.Select(r => r.Subject).ShouldBe(
            ["system-admin", "finance-officer", "internal-admin", "internal-staff", "corporate-admin", "corporate-staff", "agency-admin", "agency-staff", "report-viewer", "customer", "anonymous"]);
        matrix.Rows.Single(r => r.Subject == "agency-staff").Scopes["Booking"].ShouldBe("AgencyScope");
        matrix.Rows.Single(r => r.Subject == "report-viewer").Scopes["Booking"].ShouldBe("ViewerScope");
        matrix.Rows.Single(r => r.Subject == "customer").Scopes["Booking"].ShouldBe("CustomerScope");
        matrix.Rows.Single(r => r.Subject == "anonymous").Scopes["Booking"].ShouldBe("NoAccessScope");
        matrix.Rows.Single(r => r.Subject == "finance-officer").Allowed["POST /api/v1/bookings/{id}/cancel"].ShouldBeFalse();
        matrix.Rows.Single(r => r.Subject == "system-admin").Allowed["GET /api/v1/access-matrix"].ShouldBeTrue();
        matrix.Rows.Single(r => r.Subject == "anonymous").Allowed["GET /api/v1/bookings"].ShouldBeFalse();
    }
}
