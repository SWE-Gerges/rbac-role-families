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
public class BookingsWriteApiTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    [Theory]
    [InlineData(SeedIds.AgencyStaffA, RoleFamily.Agency, SeedIds.AgencyA1, null)]
    [InlineData(SeedIds.CorporateStaffA, RoleFamily.Corporate, null, SeedIds.CorporateA1)]
    [InlineData(SeedIds.InternalStaffA, RoleFamily.Internal, null, null)]
    [InlineData(SeedIds.SystemAdminA, RoleFamily.System, null, null)]
    public async Task Creating_a_booking_stamps_tenant_owner_family_and_account_from_the_caller(
        string userId, RoleFamily family, string? agencyId, string? corporateId)
    {
        using var client = await factory.ClientForAsync(userId);

        var response = await client.PostAsJsonAsync("/api/v1/bookings", new { type = "Flight", amount = 250.5m }, ApiFactory.Json);

        response.StatusCode.ShouldBe(HttpStatusCode.Created);
        var created = await response.ReadAsAsync<BookingResponse>();
        response.Headers.Location!.ToString().ShouldBe($"/api/v1/bookings/{created.Id}");
        created.TenantId.ShouldBe(SeedIds.TenantA);
        created.OwnerUserId.ShouldBe(userId);
        created.OwnerRoleFamilyAtCreation.ShouldBe(family);
        created.AgencyId.ShouldBe(agencyId);
        created.CorporateId.ShouldBe(corporateId);
        created.IsGuestBooking.ShouldBeFalse();
        created.Status.ShouldBe(BookingStatus.Draft);
        created.Type.ShouldBe(BookingType.Flight);
        created.Amount.ShouldBe(250.5m);

        (await client.GetAsync($"/api/v1/bookings/{created.Id}")).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_customer_booking_has_no_staff_family_and_is_only_visible_to_the_customer_and_system_admin()
    {
        using var customer = await factory.ClientForAsync(SeedIds.CustomerA);
        var created = await ApiHelpers.CreateBookingAsync(customer);

        created.OwnerRoleFamilyAtCreation.ShouldBeNull();
        created.AgencyId.ShouldBeNull();

        (await customer.GetAsync($"/api/v1/bookings/{created.Id}")).StatusCode.ShouldBe(HttpStatusCode.OK);
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        (await system.GetAsync($"/api/v1/bookings/{created.Id}")).StatusCode.ShouldBe(HttpStatusCode.OK);
        foreach (var other in new[] { SeedIds.InternalAdminA, SeedIds.AgencyAdminA, SeedIds.CorporateAdminA, SeedIds.FinanceOfficerA })
        {
            using var client = await factory.ClientForAsync(other);
            (await client.GetAsync($"/api/v1/bookings/{created.Id}")).StatusCode.ShouldBe(HttpStatusCode.NotFound, other);
        }
    }

    [Fact]
    public async Task A_new_agency_booking_is_visible_to_the_agency_admin_but_not_to_another_agency_or_internal_staff()
    {
        using var staff = await factory.ClientForAsync(SeedIds.AgencyStaffA);
        var created = await ApiHelpers.CreateBookingAsync(staff);

        using var admin = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        using var otherAgency = await factory.ClientForAsync(SeedIds.Agency2AdminA);
        using var internalStaff = await factory.ClientForAsync(SeedIds.InternalStaffA);

        (await admin.GetAsync($"/api/v1/bookings/{created.Id}")).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await otherAgency.GetAsync($"/api/v1/bookings/{created.Id}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await internalStaff.GetAsync($"/api/v1/bookings/{created.Id}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task The_request_cannot_choose_its_own_ownership()
    {
        using var client = await factory.ClientForAsync(SeedIds.AgencyStaffA);

        var response = await client.PostAsJsonAsync(
            "/api/v1/bookings",
            new { type = "Hotel", amount = 80, tenantId = SeedIds.TenantB, agencyId = SeedIds.AgencyA2, ownerUserId = "someone-else", ownerRoleFamilyAtCreation = "System" },
            ApiFactory.Json);

        var created = await response.ReadAsAsync<BookingResponse>();
        created.TenantId.ShouldBe(SeedIds.TenantA);
        created.AgencyId.ShouldBe(SeedIds.AgencyA1);
        created.OwnerUserId.ShouldBe(SeedIds.AgencyStaffA);
        created.OwnerRoleFamilyAtCreation.ShouldBe(RoleFamily.Agency);
    }

    [Theory]
    [InlineData("Hotel", 0)]
    [InlineData("Hotel", -5)]
    [InlineData("Hotel", 1000000.01)]
    [InlineData("Hotel", 10.123)]
    public async Task An_invalid_amount_is_a_400_validation_problem(string type, double amount)
    {
        using var client = await factory.ClientForAsync(SeedIds.AgencyStaffA);

        var response = await client.PostAsJsonAsync("/api/v1/bookings", new { type, amount }, ApiFactory.Json);

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await response.ReadJsonAsync()).GetProperty("errors").TryGetProperty("Amount", out _).ShouldBeTrue();
    }

    [Theory]
    [InlineData("""{"type":"Spaceship","amount":10}""")]
    [InlineData("""{"type":7,"amount":10}""")]
    [InlineData("""{"amount":"ten"}""")]
    [InlineData("not json")]
    public async Task A_malformed_body_is_a_400_problem_and_never_leaks_parser_details(string body)
    {
        using var client = await factory.ClientForAsync(SeedIds.AgencyStaffA);

        var response = await client.PostAsync("/api/v1/bookings", new StringContent(body, System.Text.Encoding.UTF8, "application/json"));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        MatrixRunner.IsProblem(response).ShouldBeTrue();
        var text = await response.Content.ReadAsStringAsync();
        text.ShouldNotContain("Exception");
        text.ShouldNotContain("   at ");
    }

    [Fact]
    public async Task An_agency_caller_whose_token_has_no_agency_cannot_create_bookings()
    {
        using var client = factory.ClientWithToken(ForgedTokens.Staff(SeedIds.AgencyStaffA, SeedIds.TenantA, "agency-staff"));

        var response = await client.PostAsJsonAsync("/api/v1/bookings", new { type = "Hotel", amount = 10 }, ApiFactory.Json);

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await response.ReadJsonAsync()).GetProperty("detail").GetString()!.ShouldContain("agency");
    }

    [Fact]
    public async Task Cancelling_a_draft_booking_in_scope_succeeds_once_and_is_then_a_conflict()
    {
        using var staff = await factory.ClientForAsync(SeedIds.AgencyStaffA);
        var created = await ApiHelpers.CreateBookingAsync(staff);

        var first = await staff.PostAsync($"/api/v1/bookings/{created.Id}/cancel", null);
        var second = await staff.PostAsync($"/api/v1/bookings/{created.Id}/cancel", null);

        first.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await first.ReadAsAsync<BookingResponse>()).Status.ShouldBe(BookingStatus.Cancelled);
        second.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        (await (await staff.GetAsync($"/api/v1/bookings/{created.Id}")).ReadAsAsync<BookingResponse>()).Status.ShouldBe(BookingStatus.Cancelled);
    }

    [Fact]
    public async Task An_agency_admin_can_cancel_a_colleagues_booking_but_another_agency_gets_a_404_and_changes_nothing()
    {
        using var staff = await factory.ClientForAsync(SeedIds.AgencyStaffA);
        var created = await ApiHelpers.CreateBookingAsync(staff);

        using var otherAgency = await factory.ClientForAsync(SeedIds.Agency2AdminA);
        (await otherAgency.PostAsync($"/api/v1/bookings/{created.Id}/cancel", null)).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await (await staff.GetAsync($"/api/v1/bookings/{created.Id}")).ReadAsAsync<BookingResponse>()).Status.ShouldBe(BookingStatus.Draft);

        using var admin = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        (await admin.PostAsync($"/api/v1/bookings/{created.Id}/cancel", null)).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Cancelling_without_the_cancel_permission_is_a_403_even_for_a_visible_booking()
    {
        using var finance = await factory.ClientForAsync(SeedIds.FinanceOfficerA);
        var visible = (await (await finance.GetAsync("/api/v1/bookings?pageSize=1")).ReadAsAsync<BookingListResponse>()).Items.Single();

        (await finance.PostAsync($"/api/v1/bookings/{visible.Id}/cancel", null)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Creating_without_the_create_permission_is_a_403()
    {
        foreach (var user in new[] { SeedIds.FinanceOfficerA, SeedIds.ReportViewerA })
        {
            using var client = await factory.ClientForAsync(user);

            var response = await client.PostAsJsonAsync("/api/v1/bookings", new { type = "Hotel", amount = 10 }, ApiFactory.Json);

            response.StatusCode.ShouldBe(HttpStatusCode.Forbidden, user);
        }
    }
}
