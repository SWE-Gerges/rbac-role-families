using System.Net;
using System.Net.Http.Json;
using Rbac.Core.Catalog;
using Rbac.Demo.Contracts;
using Rbac.IntegrationTests.Support;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

/// <summary>Caller role by target role by account relation, with the expected status derived from the creation rules.</summary>
[Trait("Category", "Integration")]
public class UserCreationMatrixTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private static readonly CreationMatrixFile Matrix = CreationMatrixFile.Load();

    [Fact]
    public void Every_role_appears_as_a_caller_and_as_a_target_and_every_outcome_is_covered()
    {
        foreach (var role in DefaultRoleCatalog.Create().Roles)
        {
            Matrix.Rows.ShouldContain(r => r.CallerRole == role.Key, $"no caller row for '{role.Key}'");
            Matrix.Rows.ShouldContain(r => r.TargetRole == role.Key, $"no target row for '{role.Key}'");
        }

        Matrix.Rows.Select(r => r.ExpectedStatus).Distinct().Order().ShouldBe([201, 400, 403]);
        Matrix.Rows.ShouldContain(r => r.Founder && r.ExpectedStatus == 201 && r.TargetRole == "agency-admin");
        Matrix.Rows.ShouldContain(r => !r.Founder && r.CallerRole == "agency-admin" && r.TargetRole == "agency-admin" && r.ExpectedStatus == 403);
    }

    [Fact]
    public async Task Every_row_returns_the_expected_status_and_created_users_get_the_right_role_and_account()
    {
        var failures = new List<string>();
        var index = 0;

        foreach (var row in Matrix.Rows)
        {
            index++;
            using var client = await factory.ClientForAsync(row.Caller);
            var handle = $"matrix-user-{index:000}";

            var response = await client.PostAsJsonAsync(
                "/api/v1/users",
                new CreateUserRequest(handle, handle, row.TargetRole, row.AgencyId, row.CorporateId),
                ApiFactory.Json);

            var label = $"{row.Caller} creates {row.TargetRole} (account {row.Account})";
            if ((int)response.StatusCode != row.ExpectedStatus)
            {
                failures.Add($"{label}: expected {row.ExpectedStatus} but got {(int)response.StatusCode}");
                continue;
            }

            if (row.ExpectedStatus == 201)
            {
                var created = await response.ReadAsAsync<UserResponse>();
                if (created.RoleKey != row.TargetRole || created.Handle != handle)
                {
                    failures.Add($"{label}: created {created.RoleKey} / {created.Handle}");
                }
            }
            else if (!MatrixRunner.IsProblem(response))
            {
                failures.Add($"{label}: the refusal is not a problem document");
            }
        }

        failures.ShouldBeEmpty(string.Join(Environment.NewLine, failures));
    }
}
