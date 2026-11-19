using Rbac.Core.Catalog;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

[Trait("Category", "Integration")]
public class AccessMatrixApiTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private static readonly AccessMatrixFile Matrix = AccessMatrixFile.Load();

    [Fact]
    public void Every_defined_role_has_rows_in_the_matrix()
    {
        foreach (var role in DefaultRoleCatalog.Create().Roles)
        {
            Matrix.List.ShouldContain(r => r.Role == role.Key, $"role '{role.Key}' has no list row");
            Matrix.Actions.ShouldContain(r => r.Role == role.Key, $"role '{role.Key}' has no action row");
        }
    }

    [Fact]
    public async Task Every_list_row_returns_exactly_the_expected_bookings_over_http()
    {
        var failures = await MatrixRunner.RunListRowsAsync(factory, Matrix);

        failures.ShouldBeEmpty(string.Join(Environment.NewLine, failures));
    }

    [Fact]
    public async Task Every_action_row_returns_the_expected_status_over_http()
    {
        var failures = await MatrixRunner.RunActionRowsAsync(factory, Matrix);

        failures.ShouldBeEmpty(string.Join(Environment.NewLine, failures));
    }

    [Fact]
    public async Task The_same_endpoint_returns_different_rows_per_role_family()
    {
        var counts = new Dictionary<string, int>();
        foreach (var user in new[] { SeedIds.SystemAdminA, SeedIds.InternalStaffA, SeedIds.AgencyAdminA, SeedIds.AgencyStaffA, SeedIds.CorporateStaffA, SeedIds.FinanceOfficerA, SeedIds.CustomerA })
        {
            using var client = await factory.ClientForAsync(user);
            var (_, ids) = await ApiHelpers.ListIdsAsync(client);
            counts[user] = ids.Count;
        }

        counts.Values.Distinct().Count().ShouldBeGreaterThanOrEqualTo(5, "roles must not collapse to the same view");
        counts[SeedIds.SystemAdminA].ShouldBe(48);
    }
}
