using System.Net.Http.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Rbac.Abstractions;
using Rbac.AspNetCore.Authorization;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;
using Rbac.Core.Management;
using Rbac.Core.Registry;
using Rbac.Core.Users;
using Rbac.Demo.AccessMatrix;
using Rbac.Demo.Contracts;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

/// <summary>
/// docs/access-matrix.md is generated, not written. These tests regenerate it in memory and fail on any difference, and check
/// that GET /api/v1/access-matrix is the same model rendered from the caller's tenant's stored role defaults.
/// </summary>
[Trait("Category", "Integration")]
public class AccessMatrixDocumentTests
{
    private const string UpdateVariable = "UPDATE_ACCESS_MATRIX";

    private static string DocumentPath => RepoPaths.FromRoot("docs", "access-matrix.md");

    private static AccessMatrixResponse BuildFromCode(ApiFactory factory, IReadOnlyList<RoleDefinition>? roles = null) => AccessMatrixBuilder.Build(
        roles ?? DefaultRoleCatalog.Create().Roles,
        factory.Services.GetRequiredService<StrategyRegistry<Booking>>(),
        factory.Services.GetRequiredService<StrategyRegistry<User>>(),
        factory.Services.GetRequiredService<RoleManagementRegistry>(),
        factory.Services.GetRequiredService<EndpointDataSource>().Endpoints);

    private static string Normalize(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal);

    [Fact]
    public void The_committed_document_is_what_the_code_generates()
    {
        using var factory = new ApiFactory();
        var generated = AccessMatrixMarkdown.Render(BuildFromCode(factory));

        if (Environment.GetEnvironmentVariable(UpdateVariable) == "1")
        {
            File.WriteAllText(DocumentPath, generated);
        }

        File.Exists(DocumentPath).ShouldBeTrue($"docs/access-matrix.md is missing. Regenerate it with: {AccessMatrixMarkdown.RegenerateCommand}");
        Normalize(File.ReadAllText(DocumentPath)).ShouldBe(
            generated,
            $"docs/access-matrix.md is out of date. Regenerate it with: {AccessMatrixMarkdown.RegenerateCommand}");
    }

    [Fact]
    public async Task The_endpoint_returns_the_same_model_so_rendering_its_response_gives_the_committed_document()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);

        var response = await (await system.GetAsync("/api/v1/access-matrix")).ReadAsAsync<AccessMatrixResponse>();

        Normalize(File.ReadAllText(DocumentPath)).ShouldBe(AccessMatrixMarkdown.Render(response));
        response.Actions.Select(a => a.Id).ShouldBe(BuildFromCode(factory).Actions.Select(a => a.Id));
    }

    [Fact]
    public async Task The_endpoint_follows_edited_role_defaults_while_the_generated_document_stays_the_code_defined_catalog()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        var role = await (await system.GetAsync($"/api/v1/roles/{RoleKeys.AgencyStaff}")).ReadAsAsync<RoleResponse>();
        (await system.PutAsJsonAsync(
            $"/api/v1/roles/{RoleKeys.AgencyStaff}/permissions",
            new SetRolePermissionsRequest([.. role.Permissions.Where(p => p != Permissions.BookingsCancel)]),
            ApiFactory.Json)).EnsureSuccessStatusCode();

        var response = await (await system.GetAsync("/api/v1/access-matrix")).ReadAsAsync<AccessMatrixResponse>();

        var row = response.Rows.Single(r => r.Subject == RoleKeys.AgencyStaff);
        row.Allowed["POST /api/v1/bookings/{id}/cancel"].ShouldBeFalse("the stored default was removed");
        row.DefaultPermissions.ShouldNotContain(Permissions.BookingsCancel);
        AccessMatrixMarkdown.Render(response).ShouldNotBe(AccessMatrixMarkdown.Render(BuildFromCode(factory)));
        Normalize(File.ReadAllText(DocumentPath)).ShouldBe(AccessMatrixMarkdown.Render(BuildFromCode(factory)));
    }

    [Fact]
    public async Task One_tenants_edit_of_a_role_default_does_not_change_another_tenants_matrix()
    {
        using var factory = new ApiFactory();
        using var systemA = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var systemB = await factory.ClientForAsync(SeedIds.SystemAdminB);
        var role = await (await systemA.GetAsync($"/api/v1/roles/{RoleKeys.AgencyStaff}")).ReadAsAsync<RoleResponse>();
        (await systemA.PutAsJsonAsync(
            $"/api/v1/roles/{RoleKeys.AgencyStaff}/permissions",
            new SetRolePermissionsRequest([.. role.Permissions.Where(p => p != Permissions.BookingsCancel)]),
            ApiFactory.Json)).EnsureSuccessStatusCode();

        var forA = await (await systemA.GetAsync("/api/v1/access-matrix")).ReadAsAsync<AccessMatrixResponse>();
        var forB = await (await systemB.GetAsync("/api/v1/access-matrix")).ReadAsAsync<AccessMatrixResponse>();

        forA.Rows.Single(r => r.Subject == RoleKeys.AgencyStaff).Allowed["POST /api/v1/bookings/{id}/cancel"].ShouldBeFalse();
        forB.Rows.Single(r => r.Subject == RoleKeys.AgencyStaff).Allowed["POST /api/v1/bookings/{id}/cancel"].ShouldBeTrue();
        Normalize(File.ReadAllText(DocumentPath)).ShouldBe(AccessMatrixMarkdown.Render(forB), "an untouched tenant still renders the committed document");
    }

    [Fact]
    public void Every_permission_gated_endpoint_is_in_the_matrix_with_the_permission_it_declares_and_the_right_resource()
    {
        using var factory = new ApiFactory();
        var matrix = BuildFromCode(factory);

        var gated = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>()
            .Where(e => e.Metadata.OfType<RequirePermissionAttribute>().Any())
            .ToList();

        matrix.Actions.Count.ShouldBe(gated.Count);
        foreach (var endpoint in gated)
        {
            var path = endpoint.RoutePattern.RawText!.TrimEnd('/');
            var method = endpoint.Metadata.GetMetadata<HttpMethodMetadata>()!.HttpMethods.Single();
            var action = matrix.Actions.Single(a => a.Id == $"{method} {path}");
            action.Permission.ShouldBe(endpoint.Metadata.OfType<RequirePermissionAttribute>().Single().Permission);

            var expectedResource = path.StartsWith("/api/v1/bookings", StringComparison.Ordinal) ? "Booking"
                : path.StartsWith("/api/v1/users", StringComparison.Ordinal) ? "User"
                : null;
            action.Resource.ShouldBe(expectedResource, $"{method} {path} must name the resource whose scope it uses");
        }
    }

    [Fact]
    public void The_matrix_lists_every_role_then_customers_and_anonymous_and_derives_each_cell_from_role_defaults()
    {
        using var factory = new ApiFactory();
        var matrix = BuildFromCode(factory);

        matrix.Rows.Select(r => r.Subject).ShouldBe([.. DefaultRoleCatalog.Create().Roles.Select(r => r.Key), "customer", "anonymous"]);
        foreach (var row in matrix.Rows)
        {
            foreach (var action in matrix.Actions)
            {
                var held = row.Subject switch
                {
                    "customer" => Permissions.CustomerDefaults.ToHashSet(),
                    "anonymous" => new HashSet<string>(),
                    _ => DefaultRoleCatalog.Create().Find(row.Subject)!.DefaultPermissions.ToHashSet(),
                };
                row.Allowed[action.Id].ShouldBe(held.Contains(action.Permission), $"{row.Subject} / {action.Id}");
            }
        }

        matrix.Rows.Single(r => r.Subject == RoleKeys.AgencyStaff).Scopes["Booking"].ShouldBe("AgencyScope");
        matrix.Rows.Single(r => r.Subject == RoleKeys.AgencyStaff).Scopes["User"].ShouldBe("AgencyUserScope");
        matrix.Rows.Single(r => r.Subject == RoleKeys.AgencyAdmin).Management.ShouldBe("AccountRoleManagement");
        matrix.Rows.Single(r => r.Subject == RoleKeys.SystemAdmin).Management.ShouldBe("CrossAccountRoleManagement");
        matrix.Rows.Single(r => r.Subject == RoleKeys.FinanceOfficer).Management.ShouldBe("DenyAllRoleManagement");
        matrix.Rows.Single(r => r.Subject == "anonymous").Allowed.Values.ShouldAllBe(allowed => !allowed);
    }

    [Fact]
    public void Rendering_fails_for_a_strategy_that_has_no_legend_entry_so_nothing_enters_the_document_undocumented()
    {
        using var factory = new ApiFactory();
        var matrix = BuildFromCode(factory);
        var unknown = matrix with
        {
            Rows = [.. matrix.Rows.Select(r => r.Subject == RoleKeys.AgencyStaff ? r with { Management = "SomeNewManagementStrategy" } : r)],
        };

        Should.Throw<InvalidOperationException>(() => AccessMatrixMarkdown.Render(unknown)).Message.ShouldContain("SomeNewManagementStrategy");
    }

    [Fact]
    public void The_document_names_every_role_every_permission_and_every_endpoint()
    {
        var text = Normalize(File.ReadAllText(DocumentPath));

        foreach (var role in DefaultRoleCatalog.Create().Roles)
        {
            text.ShouldContain($"`{role.Key}`");
        }

        foreach (var permission in Permissions.All)
        {
            text.ShouldContain($"`{permission}`");
        }

        text.ShouldContain("| GET | `/api/v1/bookings` | `bookings.read` | Booking scope |");
        text.ShouldContain("| PUT | `/api/v1/users/{id}/permissions` | `users.manage` | User scope |");
        text.ShouldContain("| GET | `/api/v1/audit` | `audit.view` | - |");
    }
}
