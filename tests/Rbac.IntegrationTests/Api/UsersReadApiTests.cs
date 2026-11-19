using System.Net;
using Rbac.Abstractions;
using Rbac.Demo.Contracts;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

[Trait("Category", "Integration")]
public class UsersReadApiTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private static readonly AccessMatrixFile Matrix = AccessMatrixFile.Load();

    [Fact]
    public async Task Every_user_list_row_returns_exactly_the_expected_users_over_http()
    {
        var failures = await MatrixRunner.RunUserListRowsAsync(factory, Matrix);

        failures.ShouldBeEmpty(string.Join(Environment.NewLine, failures));
    }

    [Fact]
    public async Task For_every_caller_and_every_user_it_is_in_the_list_exactly_when_by_id_returns_200()
    {
        var allIds = DemoSeedData.Users.Select(u => u.Id).ToArray();
        var violations = new List<string>();

        foreach (var caller in DemoSeedData.Users)
        {
            using var client = await factory.ClientForAsync(caller.Id);
            var (listStatus, listed) = await ApiHelpers.ListUserIdsAsync(client);
            var listedSet = listed.ToHashSet(StringComparer.Ordinal);

            foreach (var id in allIds)
            {
                var status = (await client.GetAsync($"/api/v1/users/{id}")).StatusCode;
                var expected = listStatus == HttpStatusCode.OK
                    ? (listedSet.Contains(id) ? HttpStatusCode.OK : HttpStatusCode.NotFound)
                    : listStatus;

                if (status != expected)
                {
                    violations.Add($"{caller.Id} -> {id}: list {(int)listStatus}, in list {listedSet.Contains(id)}, by-id {(int)status}, expected {(int)expected}");
                }
            }
        }

        violations.ShouldBeEmpty(string.Join(Environment.NewLine, violations.Take(20)));
    }

    [Fact]
    public async Task Nobody_ever_sees_a_user_of_another_tenant()
    {
        var tenantA = DemoSeedData.Users.Where(u => u.TenantId == SeedIds.TenantA).Select(u => u.Id).ToArray();
        var tenantB = DemoSeedData.Users.Where(u => u.TenantId == SeedIds.TenantB).Select(u => u.Id).ToArray();

        foreach (var (caller, foreign) in new[] { (SeedIds.SystemAdminA, tenantB), (SeedIds.SystemAdminB, tenantA), (SeedIds.InternalAdminB, tenantA) })
        {
            using var client = await factory.ClientForAsync(caller);
            var (_, listed) = await ApiHelpers.ListUserIdsAsync(client);

            listed.Intersect(foreign).ShouldBeEmpty(caller);
            foreach (var id in foreign)
            {
                (await client.GetAsync($"/api/v1/users/{id}")).StatusCode.ShouldBe(HttpStatusCode.NotFound, $"{caller} -> {id}");
            }
        }
    }

    [Fact]
    public async Task An_out_of_scope_user_and_a_missing_user_are_indistinguishable()
    {
        using var client = await factory.ClientForAsync(SeedIds.AgencyAdminA);

        var outOfScope = await client.GetAsync($"/api/v1/users/{SeedIds.SystemAdminA}");
        var missing = await client.GetAsync("/api/v1/users/usr-does-not-exist");

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
    public async Task The_user_response_shows_role_family_account_and_founder_flag()
    {
        using var client = await factory.ClientForAsync(SeedIds.InternalAdminA);

        var founder = await (await client.GetAsync($"/api/v1/users/{SeedIds.AgencyAdminA}")).ReadAsAsync<UserResponse>();
        var other = await (await client.GetAsync($"/api/v1/users/{SeedIds.AgencyAdmin2A}")).ReadAsAsync<UserResponse>();
        var customer = await (await client.GetAsync($"/api/v1/users/{SeedIds.CustomerA}")).ReadAsAsync<UserResponse>();

        founder.RoleKey.ShouldBe("agency-admin");
        founder.Family.ShouldBe(RoleFamily.Agency);
        founder.AgencyId.ShouldBe(SeedIds.AgencyA1);
        founder.IsFoundingAdmin.ShouldBeTrue();
        other.IsFoundingAdmin.ShouldBeFalse();
        customer.Kind.ShouldBe(PrincipalKind.Customer);
        customer.Family.ShouldBeNull();
        customer.RoleKey.ShouldBeNull();
    }

    [Fact]
    public async Task Users_are_paged_by_handle_and_can_be_filtered_by_role()
    {
        using var client = await factory.ClientForAsync(SeedIds.SystemAdminA);

        var first = await (await client.GetAsync("/api/v1/users?pageSize=5")).ReadAsAsync<UserListResponse>();
        var second = await (await client.GetAsync("/api/v1/users?pageSize=5&page=2")).ReadAsAsync<UserListResponse>();
        var admins = await (await client.GetAsync("/api/v1/users?role=agency-admin&pageSize=100")).ReadAsAsync<UserListResponse>();

        first.TotalCount.ShouldBe(17);
        first.Items.Count.ShouldBe(5);
        first.Items.Select(i => i.Handle).ShouldBe(first.Items.Select(i => i.Handle).Order(StringComparer.Ordinal));
        second.Items.Select(i => i.Id).Intersect(first.Items.Select(i => i.Id)).ShouldBeEmpty();
        admins.Items.Select(i => i.Id).ShouldBe([SeedIds.AgencyAdminA, SeedIds.AgencyAdmin2A, SeedIds.Agency2AdminA], ignoreOrder: true);
    }

    [Theory]
    [InlineData("page=0")]
    [InlineData("pageSize=0")]
    [InlineData("pageSize=101")]
    public async Task Invalid_paging_is_a_400_problem(string query)
    {
        using var client = await factory.ClientForAsync(SeedIds.SystemAdminA);

        var response = await client.GetAsync($"/api/v1/users?{query}");

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        MatrixRunner.IsProblem(response).ShouldBeTrue();
    }

    [Fact]
    public async Task Roles_without_users_read_get_a_403_not_an_empty_list()
    {
        foreach (var user in new[] { SeedIds.AgencyStaffA, SeedIds.FinanceOfficerA, SeedIds.ReportViewerA, SeedIds.CustomerA, SeedIds.InternalStaffA })
        {
            using var client = await factory.ClientForAsync(user);

            (await client.GetAsync("/api/v1/users")).StatusCode.ShouldBe(HttpStatusCode.Forbidden, user);
        }
    }
}
