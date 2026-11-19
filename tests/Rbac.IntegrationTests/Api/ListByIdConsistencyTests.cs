using System.Net;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

[Trait("Category", "Integration")]
public class ListByIdConsistencyTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    [Fact]
    public async Task For_every_user_and_every_booking_it_is_in_the_list_exactly_when_by_id_returns_200()
    {
        var allIds = DemoSeedData.CreateBookings(Rbac.Core.Catalog.DefaultRoleCatalog.Create()).Select(b => b.Id).ToArray();
        allIds.Length.ShouldBe(60);
        var violations = new List<string>();

        foreach (var user in DemoSeedData.Users)
        {
            using var client = await factory.ClientForAsync(user.Id);
            var (listStatus, listed) = await ApiHelpers.ListIdsAsync(client);
            var listedSet = listed.ToHashSet(StringComparer.Ordinal);

            foreach (var id in allIds)
            {
                var status = (await client.GetAsync($"/api/v1/bookings/{id}")).StatusCode;

                var expected = listStatus switch
                {
                    HttpStatusCode.OK => listedSet.Contains(id) ? HttpStatusCode.OK : HttpStatusCode.NotFound,
                    _ => listStatus,
                };

                if (status != expected)
                {
                    violations.Add($"{user.Id} {id}: list status {(int)listStatus}, in list: {listedSet.Contains(id)}, by-id {(int)status}, expected {(int)expected}");
                }
            }
        }

        violations.ShouldBeEmpty(string.Join(Environment.NewLine, violations.Take(20)));
    }

    [Fact]
    public async Task A_narrowed_list_is_always_a_subset_of_the_full_list()
    {
        foreach (var user in DemoSeedData.Users)
        {
            using var client = await factory.ClientForAsync(user.Id);
            var (fullStatus, full) = await ApiHelpers.ListIdsAsync(client);
            var (mineStatus, mine) = await ApiHelpers.ListIdsAsync(client, "mine=true");
            var (refundedStatus, refunded) = await ApiHelpers.ListIdsAsync(client, "status=Refunded");

            mineStatus.ShouldBe(fullStatus);
            refundedStatus.ShouldBe(fullStatus);
            mine.ShouldBeSubsetOf(full, user.Id);
            refunded.ShouldBeSubsetOf(full, user.Id);
        }
    }
}
