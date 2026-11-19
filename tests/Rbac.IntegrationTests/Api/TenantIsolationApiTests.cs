using System.Net;
using Rbac.Core.Catalog;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

[Trait("Category", "Integration")]
public class TenantIsolationApiTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private static readonly IReadOnlyList<Rbac.Core.Bookings.Booking> Seed = DemoSeedData.CreateBookings(DefaultRoleCatalog.Create());

    public static TheoryData<string> Users => new(DemoSeedData.Users.Select(u => u.Id));

    [Theory]
    [MemberData(nameof(Users))]
    public async Task A_user_never_sees_another_tenants_bookings_in_the_list_or_by_id(string userId)
    {
        var user = DemoSeedData.Users.Single(u => u.Id == userId);
        var foreignIds = Seed.Where(b => b.TenantId != user.TenantId).Select(b => b.Id).ToArray();
        foreignIds.ShouldNotBeEmpty();
        using var client = await factory.ClientForAsync(userId);

        var (_, listed) = await ApiHelpers.ListIdsAsync(client);

        listed.Intersect(foreignIds).ShouldBeEmpty();
        foreach (var id in foreignIds)
        {
            var response = await client.GetAsync($"/api/v1/bookings/{id}");
            response.StatusCode.ShouldBeOneOf(HttpStatusCode.NotFound, HttpStatusCode.Forbidden);
            response.StatusCode.ShouldNotBe(HttpStatusCode.OK);
        }
    }

    [Fact]
    public async Task The_tenant_comes_from_the_token_so_a_tenant_b_admin_sees_exactly_tenant_b()
    {
        using var client = await factory.ClientForAsync(SeedIds.SystemAdminB);

        var (_, ids) = await ApiHelpers.ListIdsAsync(client);

        ids.ShouldBe(Seed.Where(b => b.TenantId == SeedIds.TenantB).Select(b => b.Id), ignoreOrder: true);
    }

    [Fact]
    public async Task A_forged_token_that_moves_a_user_to_another_tenant_resolves_to_nothing()
    {
        // The user id exists only in tenant a; claiming tenant b finds no such user, so no permissions.
        using var client = factory.ClientWithToken(
            ForgedTokens.Staff(SeedIds.SystemAdminA, SeedIds.TenantB, RoleKeys.SystemAdmin));

        (await client.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Cancelling_another_tenants_booking_is_a_404_and_leaves_it_untouched()
    {
        var target = Seed.First(b => b.TenantId == SeedIds.TenantA && b.Status == Rbac.Core.Bookings.BookingStatus.Draft);
        using var attacker = await factory.ClientForAsync(SeedIds.SystemAdminB);
        using var owner = await factory.ClientForAsync(SeedIds.SystemAdminA);

        (await attacker.PostAsync($"/api/v1/bookings/{target.Id}/cancel", null)).StatusCode.ShouldBe(HttpStatusCode.NotFound);

        var stored = await (await owner.GetAsync($"/api/v1/bookings/{target.Id}")).ReadAsAsync<Rbac.Demo.Contracts.BookingResponse>();
        stored.Status.ShouldBe(Rbac.Core.Bookings.BookingStatus.Draft);
    }
}
