using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.Time.Testing;
using Rbac.Core.Catalog;
using Rbac.Demo.Contracts;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

/// <summary>Audit entries are written with the change, visible only inside the tenant and impossible to alter. Every test owns its factory.</summary>
[Trait("Category", "Integration")]
public class AuditApiTests
{
    private static async Task<AuditListResponse> ListAsync(HttpClient client, string query = "") =>
        await (await client.GetAsync($"/api/v1/audit?pageSize=100{(query.Length > 0 ? "&" : string.Empty)}{query}")).ReadAsAsync<AuditListResponse>();

    private static async Task<HttpResponseMessage> PostWithCorrelationAsync(HttpClient client, string correlationId, CreateUserRequest body)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/users") { Content = JsonContent.Create(body, options: ApiFactory.Json) };
        request.Headers.Add("X-Correlation-Id", correlationId);
        return await client.SendAsync(request);
    }

    [Fact]
    public async Task Only_roles_with_audit_view_can_read_the_trail()
    {
        using var factory = new ApiFactory();
        using var anonymous = factory.CreateClient();

        foreach (var user in new[] { SeedIds.SystemAdminA, SeedIds.InternalAdminA })
        {
            using var client = await factory.ClientForAsync(user);
            (await client.GetAsync("/api/v1/audit")).StatusCode.ShouldBe(HttpStatusCode.OK, user);
        }

        foreach (var user in new[] { SeedIds.AgencyAdminA, SeedIds.CorporateAdminA, SeedIds.FinanceOfficerA, SeedIds.AgencyStaffA, SeedIds.ReportViewerA, SeedIds.CustomerA })
        {
            using var client = await factory.ClientForAsync(user);
            (await client.GetAsync("/api/v1/audit")).StatusCode.ShouldBe(HttpStatusCode.Forbidden, user);
        }

        (await anonymous.GetAsync("/api/v1/audit")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_new_deployment_has_an_empty_trail_and_invalid_paging_is_a_400()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);

        (await ListAsync(system)).TotalCount.ShouldBe(0);
        (await system.GetAsync("/api/v1/audit?page=0")).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await system.GetAsync("/api/v1/audit?pageSize=101")).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Creating_re_roling_and_deleting_a_user_each_write_one_entry_with_actor_target_before_after_and_correlation_id()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);

        var createResponse = await PostWithCorrelationAsync(system, "trace-create-1", new CreateUserRequest("audited-user", "Audited", RoleKeys.AgencyStaff, SeedIds.AgencyA1));
        createResponse.StatusCode.ShouldBe(HttpStatusCode.Created);
        var user = await createResponse.ReadAsAsync<UserResponse>();
        (await system.PutAsJsonAsync($"/api/v1/users/{user.Id}/role", new ChangeRoleRequest(RoleKeys.AgencyAdmin, SeedIds.AgencyA1), ApiFactory.Json)).EnsureSuccessStatusCode();
        (await system.DeleteAsync($"/api/v1/users/{user.Id}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var entries = (await ListAsync(system, $"target={user.Id}")).Items;

        entries.Select(e => e.Action).Order().ShouldBe(["user.created", "user.deleted", "user.role-changed"]);
        entries.ShouldAllBe(e => e.ActorUserId == SeedIds.SystemAdminA && e.EffectiveUserId == null && e.TenantId == SeedIds.TenantA && e.TargetType == "User" && e.TargetId == user.Id);

        var created = entries.Single(e => e.Action == "user.created");
        created.CorrelationId.ShouldBe("trace-create-1");
        created.Before.ShouldBeNull();
        created.After!.Value.GetProperty("handle").GetString().ShouldBe("audited-user");
        created.After.Value.GetProperty("roleKey").GetString().ShouldBe(RoleKeys.AgencyStaff);

        var changed = entries.Single(e => e.Action == "user.role-changed");
        changed.Before!.Value.GetProperty("roleKey").GetString().ShouldBe(RoleKeys.AgencyStaff);
        changed.After!.Value.GetProperty("roleKey").GetString().ShouldBe(RoleKeys.AgencyAdmin);
        changed.CorrelationId.ShouldNotBeNullOrWhiteSpace("a correlation id is generated when the caller sends none");

        var deleted = entries.Single(e => e.Action == "user.deleted");
        deleted.Before!.Value.GetProperty("deleted").GetBoolean().ShouldBeFalse();
        deleted.After!.Value.GetProperty("deleted").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task Permission_edits_and_role_default_edits_are_audited_with_the_before_and_after_sets()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var agencyAdmin = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        var role = await (await system.GetAsync($"/api/v1/roles/{RoleKeys.AgencyStaff}")).ReadAsAsync<RoleResponse>();

        using var edit = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/users/{SeedIds.AgencyStaffA}/permissions")
        {
            Content = JsonContent.Create(new EditUserPermissionsRequest(Grant: [Permissions.BookingsViewAllAgency]), options: ApiFactory.Json),
        };
        edit.Headers.TryAddWithoutValidation("If-Match", "\"1\"");
        (await agencyAdmin.SendAsync(edit)).EnsureSuccessStatusCode();
        (await system.PutAsJsonAsync(
            $"/api/v1/roles/{RoleKeys.AgencyStaff}/permissions",
            new SetRolePermissionsRequest([.. role.Permissions.Where(p => p != Permissions.BookingsCancel)]),
            ApiFactory.Json)).EnsureSuccessStatusCode();

        var userEntry = (await ListAsync(system, $"target={SeedIds.AgencyStaffA}")).Items.Single();
        userEntry.Action.ShouldBe("user.permissions-changed");
        userEntry.ActorUserId.ShouldBe(SeedIds.AgencyAdminA);
        userEntry.Before!.Value.GetProperty("grants").GetArrayLength().ShouldBe(0);
        userEntry.After!.Value.GetProperty("grants").EnumerateArray().Select(g => g.GetString()).ShouldBe([Permissions.BookingsViewAllAgency]);
        userEntry.After.Value.GetProperty("effective").EnumerateArray().Select(g => g.GetString()).ShouldContain(Permissions.BookingsViewAllAgency);

        var roleEntry = (await ListAsync(system, $"target={RoleKeys.AgencyStaff}")).Items.Single();
        roleEntry.Action.ShouldBe("role.permissions-changed");
        roleEntry.TargetType.ShouldBe("Role");
        roleEntry.Before!.Value.GetProperty("permissions").EnumerateArray().Select(p => p.GetString()).ShouldContain(Permissions.BookingsCancel);
        roleEntry.After!.Value.GetProperty("permissions").EnumerateArray().Select(p => p.GetString()).ShouldNotContain(Permissions.BookingsCancel);
    }

    [Fact]
    public async Task Refused_and_no_op_requests_leave_no_entry()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var agencyAdmin = await factory.ClientForAsync(SeedIds.AgencyAdminA);

        (await agencyAdmin.PostAsJsonAsync("/api/v1/users", new CreateUserRequest("nope", "Nope", RoleKeys.InternalStaff), ApiFactory.Json)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await system.PostAsJsonAsync("/api/v1/users", new CreateUserRequest(SeedIds.InternalStaffA, "Duplicate", RoleKeys.InternalStaff), ApiFactory.Json)).StatusCode.ShouldBe(HttpStatusCode.Conflict);
        (await system.DeleteAsync($"/api/v1/users/{SeedIds.SystemAdminA}")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await agencyAdmin.DeleteAsync($"/api/v1/users/{SeedIds.SystemAdminA}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);

        (await ListAsync(system)).TotalCount.ShouldBe(0);
    }

    [Fact]
    public async Task An_entry_and_its_change_succeed_or_fail_together()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        await factory.ExecuteSqliteAsync(
            "CREATE TRIGGER \"AuditEntry_fail_for_test\" BEFORE INSERT ON \"AuditEntry\" BEGIN SELECT RAISE(ABORT, 'audit store unavailable'); END;");

        var response = await system.PostAsJsonAsync("/api/v1/users", new CreateUserRequest("never-created", "Never", RoleKeys.InternalStaff), ApiFactory.Json);

        response.StatusCode.ShouldBe(HttpStatusCode.InternalServerError);
        (await response.Content.ReadAsStringAsync()).ShouldNotContain("audit store unavailable", Case.Insensitive);
        (await factory.ScalarSqliteAsync("SELECT COUNT(*) FROM \"User\" WHERE \"Handle\" = 'never-created'")).ShouldBe(0, "the user insert rolled back with the failed audit insert");

        await factory.ExecuteSqliteAsync("DROP TRIGGER \"AuditEntry_fail_for_test\"");
        (await system.PostAsJsonAsync("/api/v1/users", new CreateUserRequest("created-now", "Now", RoleKeys.InternalStaff), ApiFactory.Json)).StatusCode.ShouldBe(HttpStatusCode.Created);
        (await ListAsync(system)).TotalCount.ShouldBe(1);
    }

    [Fact]
    public async Task The_trail_is_tenant_scoped_filterable_and_newest_first()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        using var factory = ApiFactory.With(new ApiFactoryOptions { Clock = clock });
        using var systemA = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var internalA = await factory.ClientForAsync(SeedIds.InternalAdminA);
        using var systemB = await factory.ClientForAsync(SeedIds.SystemAdminB);

        var first = await ApiHelpers.CreateUserAsync(systemA, "first-user", RoleKeys.InternalStaff);
        clock.Advance(TimeSpan.FromSeconds(1));
        var second = await ApiHelpers.CreateUserAsync(internalA, "second-user", RoleKeys.InternalStaff);
        clock.Advance(TimeSpan.FromSeconds(1));
        await ApiHelpers.CreateUserAsync(systemB, "other-tenant-user", RoleKeys.InternalStaff);

        var all = await ListAsync(systemA);
        all.TotalCount.ShouldBe(2, "tenant B's entry is not visible");
        all.Items.Select(e => e.TargetId).ShouldBe([second.Id, first.Id], "newest first");
        all.Items.ShouldAllBe(e => e.TenantId == SeedIds.TenantA);

        (await ListAsync(systemA, $"actor={SeedIds.InternalAdminA}")).Items.Select(e => e.TargetId).ShouldBe([second.Id]);
        (await ListAsync(systemA, $"target={first.Id}")).Items.ShouldHaveSingleItem().ActorUserId.ShouldBe(SeedIds.SystemAdminA);
        (await ListAsync(systemA, "target=nobody")).TotalCount.ShouldBe(0);
        (await ListAsync(systemB)).Items.ShouldHaveSingleItem().TenantId.ShouldBe(SeedIds.TenantB);

        var paged = await (await systemA.GetAsync("/api/v1/audit?pageSize=1&page=2")).ReadAsAsync<AuditListResponse>();
        paged.Items.Select(e => e.TargetId).ShouldBe([first.Id]);
        paged.TotalCount.ShouldBe(2);
    }

    [Fact]
    public async Task The_api_offers_no_way_to_change_or_remove_entries_and_the_database_refuses_it_too()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        await ApiHelpers.CreateUserAsync(system, "audited-for-tamper-test", RoleKeys.InternalStaff);
        var entry = (await ListAsync(system)).Items.Single();

        foreach (var method in new[] { HttpMethod.Put, HttpMethod.Delete, HttpMethod.Patch, HttpMethod.Post })
        {
            using var request = new HttpRequestMessage(method, $"/api/v1/audit/{entry.Id}");
            (await system.SendAsync(request)).StatusCode.ShouldBeOneOf(HttpStatusCode.NotFound, HttpStatusCode.MethodNotAllowed);
        }

        var update = await Should.ThrowAsync<Microsoft.Data.Sqlite.SqliteException>(() => factory.ExecuteSqliteAsync("UPDATE \"AuditEntry\" SET \"Action\" = 'tampered'"));
        var delete = await Should.ThrowAsync<Microsoft.Data.Sqlite.SqliteException>(() => factory.ExecuteSqliteAsync("DELETE FROM \"AuditEntry\""));
        update.Message.ShouldContain("append-only");
        delete.Message.ShouldContain("append-only");
        (await ListAsync(system)).Items.Single().Action.ShouldBe("user.created");
    }
}
