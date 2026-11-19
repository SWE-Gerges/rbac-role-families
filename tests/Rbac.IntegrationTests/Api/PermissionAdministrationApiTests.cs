using System.Net;
using System.Net.Http.Json;
using Rbac.Core.Catalog;
using Rbac.Demo.Contracts;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

/// <summary>
/// The permission catalog, role defaults and per-user overrides. Every test owns its factory because each successful edit
/// revokes sessions (token versions bump), which would break later tests that reuse a cached token on a shared fixture.
/// </summary>
[Trait("Category", "Integration")]
public class PermissionAdministrationApiTests
{
    private static async Task<(UserPermissionsResponse Body, string? ETag)> ReadAsync(HttpClient client, string userId)
    {
        var response = await client.GetAsync($"/api/v1/users/{userId}/permissions");
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        return (await response.ReadAsAsync<UserPermissionsResponse>(), response.Headers.ETag?.Tag);
    }

    private static async Task<HttpResponseMessage> EditAsync(
        HttpClient client, string userId, string? ifMatch, string[]? grant = null, string[]? revoke = null, string[]? reset = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/users/{userId}/permissions")
        {
            Content = JsonContent.Create(new EditUserPermissionsRequest(grant, revoke, reset), options: ApiFactory.Json),
        };
        if (ifMatch is not null)
        {
            request.Headers.TryAddWithoutValidation("If-Match", ifMatch);
        }

        return await client.SendAsync(request);
    }

    private static async Task<HttpResponseMessage> SetRoleAsync(HttpClient client, string roleKey, params string[]? permissions) =>
        await client.PutAsJsonAsync($"/api/v1/roles/{roleKey}/permissions", new SetRolePermissionsRequest(permissions), ApiFactory.Json);

    [Fact]
    public async Task The_catalog_lists_every_permission_and_marks_the_reserved_one()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);

        var catalog = await (await system.GetAsync("/api/v1/permissions")).ReadAsAsync<List<PermissionResponse>>();

        catalog.Select(p => p.Key).ShouldBe(Permissions.All, ignoreOrder: true);
        catalog.Single(p => p.Reserved).Key.ShouldBe(Permissions.RolesManagePermissions);
        catalog.ShouldAllBe(p => p.Description.Length > 0);
    }

    [Fact]
    public async Task Roles_are_listed_from_the_stored_rows_with_their_defaults_and_creation_graph()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);

        var roles = await (await system.GetAsync("/api/v1/roles")).ReadAsAsync<List<RoleResponse>>();
        var one = await (await system.GetAsync($"/api/v1/roles/{RoleKeys.AgencyAdmin}")).ReadAsAsync<RoleResponse>();

        roles.Select(r => r.Key).ShouldBe(DefaultRoleCatalog.Create().Roles.Select(r => r.Key), ignoreOrder: true);
        one.IsAdmin.ShouldBeTrue();
        one.CreatableRoleKeys.ShouldBe([RoleKeys.AgencyAdmin, RoleKeys.AgencyStaff], ignoreOrder: true);
        one.Permissions.ShouldContain(Permissions.BookingsViewAllAgency);
        (await system.GetAsync("/api/v1/roles/no-such-role")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Reading_the_catalog_needs_permissions_view()
    {
        using var factory = new ApiFactory();
        using var staff = await factory.ClientForAsync(SeedIds.AgencyStaffA);
        using var anonymous = factory.CreateClient();

        (await staff.GetAsync("/api/v1/permissions")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await staff.GetAsync("/api/v1/roles")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await anonymous.GetAsync("/api/v1/permissions")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_grant_widens_the_users_scope_after_their_sessions_are_revoked_and_the_response_carries_the_new_version()
    {
        using var factory = new ApiFactory();
        using var admin = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        using var oldSession = await factory.ClientForAsync(SeedIds.AgencyStaffA);
        var (_, before) = await ApiHelpers.ListIdsAsync(oldSession);
        var (read, etag) = await ReadAsync(admin, SeedIds.AgencyStaffA);
        etag.ShouldBe("\"1\"");
        read.Effective.ShouldNotContain(Permissions.BookingsViewAllAgency);

        var response = await EditAsync(admin, SeedIds.AgencyStaffA, etag, grant: [Permissions.BookingsViewAllAgency]);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        response.Headers.ETag!.Tag.ShouldBe("\"2\"");
        var edited = await response.ReadAsAsync<UserPermissionsResponse>();
        edited.Version.ShouldBe(2);
        edited.Grants.ShouldBe([Permissions.BookingsViewAllAgency]);
        edited.Effective.ShouldContain(Permissions.BookingsViewAllAgency);
        edited.RoleDefaults.ShouldNotContain(Permissions.BookingsViewAllAgency);

        (await oldSession.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        using var newSession = await factory.ClientForAsync(SeedIds.AgencyStaffA, freshToken: true);
        var (_, after) = await ApiHelpers.ListIdsAsync(newSession);
        after.Count.ShouldBeGreaterThan(before.Count);
        before.ShouldBeSubsetOf(after);
    }

    [Fact]
    public async Task A_revoke_takes_effect_on_the_next_request_with_a_fresh_token_and_never_with_the_old_one()
    {
        using var factory = new ApiFactory();
        using var admin = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        using var oldSession = await factory.ClientForAsync(SeedIds.AgencyStaffA);
        var draft = await ApiHelpers.CreateBookingAsync(oldSession);
        var (_, etag) = await ReadAsync(admin, SeedIds.AgencyStaffA);

        (await EditAsync(admin, SeedIds.AgencyStaffA, etag, revoke: [Permissions.BookingsCancel])).StatusCode.ShouldBe(HttpStatusCode.OK);

        (await oldSession.PostAsync($"/api/v1/bookings/{draft.Id}/cancel", null)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        using var newSession = await factory.ClientForAsync(SeedIds.AgencyStaffA, freshToken: true);
        (await newSession.PostAsync($"/api/v1/bookings/{draft.Id}/cancel", null)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await newSession.GetAsync($"/api/v1/bookings/{draft.Id}")).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await (await newSession.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>()).Permissions.ShouldNotContain(Permissions.BookingsCancel);
    }

    [Fact]
    public async Task A_diff_can_grant_revoke_and_reset_in_one_call_and_reports_the_overrides()
    {
        using var factory = new ApiFactory();
        using var admin = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        var (_, etag) = await ReadAsync(admin, SeedIds.AgencyStaffViewAllA);

        // The seeded user already holds a bookings.view-all-agency grant; reset it, and revoke a role default.
        var response = await EditAsync(
            admin,
            SeedIds.AgencyStaffViewAllA,
            etag,
            revoke: [Permissions.BookingsCreate],
            reset: [Permissions.BookingsViewAllAgency]);

        var edited = await response.ReadAsAsync<UserPermissionsResponse>();
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        edited.Grants.ShouldBeEmpty();
        edited.Revokes.ShouldBe([Permissions.BookingsCreate]);
        edited.Effective.ShouldBe([Permissions.BookingsCancel, Permissions.BookingsRead]);
    }

    [Fact]
    public async Task A_no_op_diff_changes_no_version_and_does_not_revoke_sessions()
    {
        using var factory = new ApiFactory();
        using var admin = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        using var session = await factory.ClientForAsync(SeedIds.AgencyStaffA);
        var (_, etag) = await ReadAsync(admin, SeedIds.AgencyStaffA);

        var response = await EditAsync(admin, SeedIds.AgencyStaffA, etag, grant: [Permissions.BookingsRead], revoke: [Permissions.BookingsViewAllAgency]);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await response.ReadAsAsync<UserPermissionsResponse>()).Version.ShouldBe(1);
        (await session.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await factory.ScalarSqliteAsync("SELECT COUNT(*) FROM \"AuditEntry\" WHERE \"Action\" = 'user.permissions-changed'")).ShouldBe(0);
    }

    [Fact]
    public async Task Escalation_is_refused_for_permissions_the_caller_does_not_hold_and_nothing_changes()
    {
        using var factory = new ApiFactory();
        using var agencyAdmin = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        var (_, agencyEtag) = await ReadAsync(agencyAdmin, SeedIds.AgencyStaffA);
        var (_, systemEtag) = await ReadAsync(system, SeedIds.AgencyStaffA);

        var attempts = new (string Label, HttpResponseMessage Response)[]
        {
            ("agency admin grants reports.view", await EditAsync(agencyAdmin, SeedIds.AgencyStaffA, agencyEtag, grant: [Permissions.ReportsView])),
            ("agency admin grants users.act-on-behalf", await EditAsync(agencyAdmin, SeedIds.AgencyStaffA, agencyEtag, grant: [Permissions.UsersActOnBehalf])),
            ("agency admin grants audit.view", await EditAsync(agencyAdmin, SeedIds.AgencyStaffA, agencyEtag, grant: [Permissions.AuditView])),
            ("system admin lacks bookings.view-all-agency", await EditAsync(system, SeedIds.AgencyStaffA, systemEtag, grant: [Permissions.BookingsViewAllAgency])),
            ("system admin lacks bookings.view-all-corporate", await EditAsync(system, SeedIds.CorporateStaffA, systemEtag, grant: [Permissions.BookingsViewAllCorporate])),
            ("system admin grants the reserved permission", await EditAsync(system, SeedIds.AgencyStaffA, systemEtag, grant: [Permissions.RolesManagePermissions])),
            ("revoking what you do not hold", await EditAsync(system, SeedIds.AgencyStaffViewAllA, systemEtag, revoke: [Permissions.BookingsViewAllAgency])),
            ("resetting what you do not hold", await EditAsync(system, SeedIds.AgencyStaffViewAllA, systemEtag, reset: [Permissions.BookingsViewAllAgency])),
        };

        foreach (var (label, response) in attempts)
        {
            response.StatusCode.ShouldBe(HttpStatusCode.Forbidden, label);
            MatrixRunner.IsProblem(response).ShouldBeTrue(label);
        }

        var (unchanged, etag) = await ReadAsync(agencyAdmin, SeedIds.AgencyStaffA);
        etag.ShouldBe("\"1\"");
        unchanged.Grants.ShouldBeEmpty();
        unchanged.Revokes.ShouldBeEmpty();
        (await factory.ScalarSqliteAsync("SELECT COUNT(*) FROM \"UserPermission\" WHERE \"UserId\" = 'a-agency-staff'")).ShouldBe(0);
    }

    [Fact]
    public async Task A_caller_cannot_edit_their_own_permissions_or_users_outside_their_management_scope()
    {
        using var factory = new ApiFactory();
        using var plainAdmin = await factory.ClientForAsync(SeedIds.AgencyAdmin2A);
        using var agencyAdmin = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);

        (await EditAsync(plainAdmin, SeedIds.AgencyAdmin2A, "\"1\"", grant: [Permissions.BookingsRead])).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await EditAsync(plainAdmin, SeedIds.AgencyAdminA, "\"1\"", revoke: [Permissions.BookingsCreate])).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await EditAsync(agencyAdmin, SeedIds.CorporateStaffA, "\"1\"", grant: [Permissions.BookingsRead])).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await EditAsync(agencyAdmin, SeedIds.SystemAdminA, "\"1\"", grant: [Permissions.BookingsRead])).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await EditAsync(system, SeedIds.SystemAdminA, "\"1\"", revoke: [Permissions.BookingsCreate])).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await agencyAdmin.GetAsync($"/api/v1/users/{SeedIds.CorporateStaffA}/permissions")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Another_tenants_user_is_a_404_for_reads_and_edits()
    {
        using var factory = new ApiFactory();
        using var foreign = await factory.ClientForAsync(SeedIds.SystemAdminB);

        (await foreign.GetAsync($"/api/v1/users/{SeedIds.AgencyStaffA}/permissions")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await EditAsync(foreign, SeedIds.AgencyStaffA, "\"1\"", grant: [Permissions.BookingsRead])).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task A_stale_or_missing_version_is_refused_so_two_editors_cannot_overwrite_each_other()
    {
        using var factory = new ApiFactory();
        using var internalAdmin = await factory.ClientForAsync(SeedIds.InternalAdminA);
        using var agencyAdmin = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        var (_, etagForBoth) = await ReadAsync(internalAdmin, SeedIds.AgencyStaffA);

        (await EditAsync(agencyAdmin, SeedIds.AgencyStaffA, null, grant: [Permissions.BookingsViewAllAgency])).StatusCode.ShouldBe((HttpStatusCode)428);
        (await EditAsync(agencyAdmin, SeedIds.AgencyStaffA, etagForBoth, grant: [Permissions.BookingsViewAllAgency])).StatusCode.ShouldBe(HttpStatusCode.OK);

        var late = await EditAsync(internalAdmin, SeedIds.AgencyStaffA, etagForBoth, revoke: [Permissions.BookingsCancel]);
        late.StatusCode.ShouldBe(HttpStatusCode.PreconditionFailed);
        MatrixRunner.IsProblem(late).ShouldBeTrue();
        (await EditAsync(internalAdmin, SeedIds.AgencyStaffA, "not-a-version", revoke: [Permissions.BookingsCancel])).StatusCode.ShouldBe(HttpStatusCode.PreconditionFailed);

        var (current, etag) = await ReadAsync(internalAdmin, SeedIds.AgencyStaffA);
        current.Revokes.ShouldBeEmpty("the stale edit must not have been applied");
        (await EditAsync(internalAdmin, SeedIds.AgencyStaffA, $"W/{etag}", revoke: [Permissions.BookingsCancel])).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Invalid_diffs_are_400_problems()
    {
        using var factory = new ApiFactory();
        using var admin = await factory.ClientForAsync(SeedIds.AgencyAdminA);

        var unknown = await EditAsync(admin, SeedIds.AgencyStaffA, "\"1\"", grant: ["bookings.not_a_permission"]);
        var twoLists = await EditAsync(admin, SeedIds.AgencyStaffA, "\"1\"", grant: [Permissions.BookingsRead], revoke: [Permissions.BookingsRead]);

        unknown.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        twoLists.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        MatrixRunner.IsProblem(unknown).ShouldBeTrue();
    }

    [Fact]
    public async Task Editing_a_role_default_changes_only_the_callers_tenant_and_revokes_only_that_tenants_sessions()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var tenantAStaff = await factory.ClientForAsync(SeedIds.AgencyStaffA);
        using var tenantBStaff = await factory.ClientForAsync(SeedIds.AgencyStaffB);
        using var tenantBAdmin = await factory.ClientForAsync(SeedIds.AgencyAdminB);
        var role = await (await system.GetAsync($"/api/v1/roles/{RoleKeys.AgencyStaff}")).ReadAsAsync<RoleResponse>();

        var response = await SetRoleAsync(system, RoleKeys.AgencyStaff, [.. role.Permissions.Where(p => p != Permissions.BookingsCancel)]);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await response.ReadAsAsync<RoleResponse>()).Permissions.ShouldNotContain(Permissions.BookingsCancel);
        (await (await system.GetAsync($"/api/v1/roles/{RoleKeys.AgencyStaff}")).ReadAsAsync<RoleResponse>()).Permissions.ShouldNotContain(Permissions.BookingsCancel);
        (await tenantAStaff.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "tenant A's holders are revoked");

        using var freshA = await factory.ClientForAsync(SeedIds.AgencyStaffA, freshToken: true);
        (await (await freshA.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>()).Permissions.ShouldNotContain(Permissions.BookingsCancel);

        // Tenant B: same session, same permissions, same role view, same versions, nothing audited.
        var meB = await (await tenantBStaff.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>();
        meB.Permissions.ShouldContain(Permissions.BookingsCancel);
        meB.TokenVersion.ShouldBe(1);
        (await (await tenantBAdmin.GetAsync($"/api/v1/roles/{RoleKeys.AgencyStaff}")).ReadAsAsync<RoleResponse>()).Permissions.ShouldContain(Permissions.BookingsCancel);
        (await ReadAsync(tenantBAdmin, SeedIds.AgencyStaffB)).Body.Version.ShouldBe(1);
        (await factory.ScalarSqliteAsync("SELECT COUNT(*) FROM \"TokenVersion\" WHERE \"TenantId\" = 'tenant-b'")).ShouldBe(0);

        using var adminA = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        (await ReadAsync(adminA, SeedIds.AgencyStaffA)).Body.Version.ShouldBe(2, "a role default change moves its own tenant's holders' permission versions");
    }

    [Fact]
    public async Task A_tenant_b_system_admin_editing_a_role_leaves_tenant_a_untouched_and_is_audited_in_tenant_b()
    {
        using var factory = new ApiFactory();
        using var systemB = await factory.ClientForAsync(SeedIds.SystemAdminB);
        using var systemA = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var viewerA = await factory.ClientForAsync(SeedIds.ReportViewerA);
        using var viewerB = await factory.ClientForAsync(SeedIds.ReportViewerB);
        (await viewerA.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        var rowsOfAAtStart = await factory.ScalarSqliteAsync("SELECT COUNT(*) FROM \"RolePermission\" WHERE \"TenantId\" = 'tenant-a'");

        var response = await SetRoleAsync(systemB, RoleKeys.ReportViewer, Permissions.ReportsView, Permissions.BookingsRead);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        // Tenant B got the change and its holders were revoked.
        (await viewerB.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        using var freshViewerB = await factory.ClientForAsync(SeedIds.ReportViewerB, freshToken: true);
        (await freshViewerB.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.OK);

        // Tenant A is exactly as before: session, permissions, bookings, versions, stored rows.
        var meA = await (await viewerA.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>();
        meA.Permissions.ShouldBe([Permissions.ReportsView]);
        meA.TokenVersion.ShouldBe(1);
        (await viewerA.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await (await systemA.GetAsync($"/api/v1/roles/{RoleKeys.ReportViewer}")).ReadAsAsync<RoleResponse>()).Permissions.ShouldBe([Permissions.ReportsView]);
        (await ReadAsync(systemA, SeedIds.ReportViewerA)).Body.Version.ShouldBe(1);
        (await factory.ScalarSqliteAsync("SELECT COUNT(*) FROM \"TokenVersion\" WHERE \"TenantId\" = 'tenant-a'")).ShouldBe(0);
        (await factory.ScalarSqliteAsync("SELECT COUNT(*) FROM \"RolePermission\" WHERE \"TenantId\" = 'tenant-a'")).ShouldBe(rowsOfAAtStart);
        (await factory.ScalarSqliteAsync("SELECT COUNT(*) FROM \"RolePermission\" WHERE \"TenantId\" = 'tenant-a' AND \"RoleKey\" = 'report-viewer'")).ShouldBe(1);

        // The audit entry is in tenant B, and only there.
        (await factory.ScalarSqliteAsync("SELECT COUNT(*) FROM \"AuditEntry\" WHERE \"TenantId\" = 'tenant-a'")).ShouldBe(0);
        var auditB = await (await systemB.GetAsync($"/api/v1/audit?target={RoleKeys.ReportViewer}")).ReadAsAsync<AuditListResponse>();
        auditB.Items.ShouldHaveSingleItem().Action.ShouldBe("role.permissions-changed");
        auditB.Items[0].TenantId.ShouldBe(SeedIds.TenantB);
        auditB.Items[0].ActorUserId.ShouldBe(SeedIds.SystemAdminB);
        (await (await systemA.GetAsync("/api/v1/audit?pageSize=100")).ReadAsAsync<AuditListResponse>()).TotalCount.ShouldBe(0);
    }

    [Fact]
    public async Task A_tenant_admin_cannot_reach_another_tenants_role_defaults_by_naming_the_tenant_or_the_role_keys()
    {
        using var factory = new ApiFactory();
        using var systemB = await factory.ClientForAsync(SeedIds.SystemAdminB);
        using var systemA = await factory.ClientForAsync(SeedIds.SystemAdminA);
        var tenantAStart = await systemA.GetAsync($"/api/v1/roles/{RoleKeys.AgencyStaff}");
        var before = await tenantAStart.ReadAsAsync<RoleResponse>();

        // Role keys are global names, so guessing them is possible; there is no way to say whose defaults they mean. Every
        // attempt to point at tenant A (body, query string, headers, an on-behalf target) lands on tenant B or is refused.
        using var request = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/roles/{RoleKeys.AgencyStaff}/permissions?tenantId={SeedIds.TenantA}")
        {
            Content = JsonContent.Create(new { tenantId = SeedIds.TenantA, permissions = new[] { Permissions.BookingsRead } }, options: ApiFactory.Json),
        };
        request.Headers.Add("X-Tenant-Id", SeedIds.TenantA);
        (await systemB.SendAsync(request)).StatusCode.ShouldBe(HttpStatusCode.OK);

        (await (await systemB.GetAsync($"/api/v1/roles/{RoleKeys.AgencyStaff}")).ReadAsAsync<RoleResponse>()).Permissions.ShouldBe([Permissions.BookingsRead]);
        (await (await systemA.GetAsync($"/api/v1/roles/{RoleKeys.AgencyStaff}")).ReadAsAsync<RoleResponse>()).Permissions.ShouldBe(before.Permissions);

        using var onBehalf = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/roles/{RoleKeys.AgencyStaff}/permissions")
        {
            Content = JsonContent.Create(new SetRolePermissionsRequest([Permissions.BookingsRead]), options: ApiFactory.Json),
        };
        onBehalf.Headers.Add("X-On-Behalf-Of", SeedIds.SystemAdminA);
        (await systemB.SendAsync(onBehalf)).StatusCode.ShouldBe(HttpStatusCode.NotFound, "a tenant A user does not exist for a tenant B caller");
        (await (await systemA.GetAsync($"/api/v1/roles/{RoleKeys.AgencyStaff}")).ReadAsAsync<RoleResponse>()).Permissions.ShouldBe(before.Permissions);
        (await factory.ScalarSqliteAsync("SELECT COUNT(*) FROM \"RolePermission\" WHERE \"TenantId\" = 'tenant-a' AND \"RoleKey\" = 'agency-staff'")).ShouldBe(before.Permissions.Count);
    }

    [Fact]
    public async Task Tenant_a_editing_a_role_leaves_tenant_b_untouched_in_the_other_direction_too()
    {
        using var factory = new ApiFactory();
        using var systemA = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var staffB = await factory.ClientForAsync(SeedIds.CorporateStaffB);
        var before = await (await staffB.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>();
        var idsBefore = (await ApiHelpers.ListIdsAsync(staffB)).Ids;

        (await SetRoleAsync(systemA, RoleKeys.CorporateStaff, Permissions.BookingsRead)).StatusCode.ShouldBe(HttpStatusCode.OK);

        var after = await (await staffB.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>();
        after.Permissions.ShouldBe(before.Permissions);
        after.TokenVersion.ShouldBe(before.TokenVersion);
        (await ApiHelpers.ListIdsAsync(staffB)).Ids.ShouldBe(idsBefore);
        (await factory.ScalarSqliteAsync("SELECT COUNT(*) FROM \"AuditEntry\" WHERE \"TenantId\" = 'tenant-b'")).ShouldBe(0);
    }

    [Fact]
    public async Task A_role_default_edit_cannot_escalate_delegate_the_reserved_permission_or_lock_out_the_system_role()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        var agencyStaff = await (await system.GetAsync($"/api/v1/roles/{RoleKeys.AgencyStaff}")).ReadAsAsync<RoleResponse>();
        var systemAdmin = await (await system.GetAsync($"/api/v1/roles/{RoleKeys.SystemAdmin}")).ReadAsAsync<RoleResponse>();

        var attempts = new (string Label, HttpResponseMessage Response)[]
        {
            ("a permission the system admin does not hold", await SetRoleAsync(system, RoleKeys.FinanceOfficer, [Permissions.BookingsRead, Permissions.BookingsViewAllAgency])),
            ("the reserved permission on a non-system role", await SetRoleAsync(system, RoleKeys.AgencyStaff, [.. agencyStaff.Permissions, Permissions.RolesManagePermissions])),
            ("removing the reserved permission from the system role", await SetRoleAsync(system, RoleKeys.SystemAdmin, [.. systemAdmin.Permissions.Where(p => p != Permissions.RolesManagePermissions)])),
        };

        foreach (var (label, response) in attempts)
        {
            response.StatusCode.ShouldBe(HttpStatusCode.Forbidden, label);
        }

        (await system.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.OK, "a refused edit revokes nobody");
        (await (await system.GetAsync($"/api/v1/roles/{RoleKeys.SystemAdmin}")).ReadAsAsync<RoleResponse>()).Permissions.ShouldContain(Permissions.RolesManagePermissions);
    }

    [Fact]
    public async Task Only_system_admins_can_edit_role_defaults_and_bad_input_is_a_problem()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var internalAdmin = await factory.ClientForAsync(SeedIds.InternalAdminA);
        using var agencyAdmin = await factory.ClientForAsync(SeedIds.AgencyAdminA);

        (await SetRoleAsync(internalAdmin, RoleKeys.AgencyStaff, Permissions.BookingsRead)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await SetRoleAsync(agencyAdmin, RoleKeys.AgencyStaff, Permissions.BookingsRead)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await SetRoleAsync(system, "no-such-role", Permissions.BookingsRead)).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await SetRoleAsync(system, RoleKeys.AgencyStaff, "bookings.not_a_permission")).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await SetRoleAsync(system, RoleKeys.AgencyStaff, permissions: null)).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Setting_a_role_to_the_permissions_it_already_has_changes_nothing()
    {
        using var factory = new ApiFactory();
        using var system = await factory.ClientForAsync(SeedIds.SystemAdminA);
        using var staff = await factory.ClientForAsync(SeedIds.AgencyStaffA);
        var role = await (await system.GetAsync($"/api/v1/roles/{RoleKeys.AgencyStaff}")).ReadAsAsync<RoleResponse>();

        (await SetRoleAsync(system, RoleKeys.AgencyStaff, [.. role.Permissions.Reverse()])).StatusCode.ShouldBe(HttpStatusCode.OK);

        (await staff.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.OK, "no change, no revocation");
    }
}
