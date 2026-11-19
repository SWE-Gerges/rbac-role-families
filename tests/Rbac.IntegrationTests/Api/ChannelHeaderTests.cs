using System.Net;
using Rbac.Demo.Contracts;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

[Trait("Category", "Integration")]
public class ChannelHeaderTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private const string Header = "X-Client-Channel";

    [Theory]
    [InlineData(SeedIds.SystemAdminA)]
    [InlineData(SeedIds.AgencyStaffA)]
    [InlineData(SeedIds.CorporateStaffA)]
    [InlineData(SeedIds.FinanceOfficerA)]
    [InlineData(SeedIds.CustomerA)]
    [InlineData(SeedIds.ReportViewerA)]
    public async Task The_channel_header_never_changes_what_a_caller_may_see_or_do(string userId)
    {
        using var plain = await factory.ClientForAsync(userId);
        var (baselineStatus, baseline) = await ApiHelpers.ListIdsAsync(plain);
        var baselineById = (await plain.GetAsync("/api/v1/bookings/bk-a-001")).StatusCode;
        var baselineMatrix = (await plain.GetAsync("/api/v1/access-matrix")).StatusCode;

        foreach (var channel in new[] { "web", "app", "back-office", "BACK-OFFICE", "admin", "system", "", "web, back-office" })
        {
            using var client = await factory.ClientForAsync(userId);
            client.DefaultRequestHeaders.TryAddWithoutValidation(Header, channel);

            var (status, ids) = await ApiHelpers.ListIdsAsync(client);

            status.ShouldBe(baselineStatus, $"{userId} / '{channel}'");
            ids.ShouldBe(baseline, $"{userId} / '{channel}'");
            (await client.GetAsync("/api/v1/bookings/bk-a-001")).StatusCode.ShouldBe(baselineById);
            (await client.GetAsync("/api/v1/access-matrix")).StatusCode.ShouldBe(baselineMatrix);
        }
    }

    [Fact]
    public async Task Claiming_to_be_the_back_office_does_not_unlock_anything()
    {
        using var client = await factory.ClientForAsync(SeedIds.AgencyStaffA);
        client.DefaultRequestHeaders.Add(Header, "back-office");

        (await client.GetAsync("/api/v1/bookings/bk-a-001")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await client.GetAsync("/api/v1/access-matrix")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Theory]
    [InlineData("web", "web")]
    [InlineData("APP", "app")]
    [InlineData("back-office", "back-office")]
    [InlineData("hacker", null)]
    public async Task The_header_is_only_echoed_back_as_a_presentation_hint_when_it_is_a_known_channel(string header, string? expected)
    {
        using var client = await factory.ClientForAsync(SeedIds.AgencyStaffA);
        client.DefaultRequestHeaders.Add(Header, header);

        var page = await (await client.GetAsync("/api/v1/bookings")).ReadAsAsync<BookingListResponse>();

        page.ChannelHint.ShouldBe(expected);
    }
}
