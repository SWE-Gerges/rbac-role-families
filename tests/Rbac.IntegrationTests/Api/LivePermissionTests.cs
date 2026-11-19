using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Rbac.Abstractions;
using Rbac.Core.Catalog;
using Rbac.Demo.Contracts;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence;
using Rbac.Persistence.Caching;
using Rbac.Persistence.Entities;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

[Trait("Category", "Integration")]
public class LivePermissionTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    /// <summary>
    /// Edits rows the way an operator would. Permissions are cached per principal and validated against the tenant's persisted
    /// epoch, so a write that bypasses the application has to move the epoch too; that is part of the contract, and
    /// the cache tests show what happens when it does not.
    /// </summary>
    private async Task WithDbAsync(Func<RbacDbContext, Task> action, params string[] bumpTenants)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<RbacDbContext>();
        await action(db);
        foreach (var tenant in bumpTenants)
        {
            await PermissionEpoch.BumpAsync(db, tenant, CancellationToken.None);
        }
    }

    [Fact]
    public async Task A_permission_revoked_in_the_database_takes_effect_for_the_same_token_on_the_next_request()
    {
        const string user = SeedIds.InternalStaffB;
        using var client = await factory.ClientForAsync(user);
        var draft = await ApiHelpers.CreateBookingAsync(client);
        (await client.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.OK);

        await WithDbAsync(async db =>
        {
            db.UserPermissions.Add(new UserPermissionEntity
            {
                TenantId = SeedIds.TenantB,
                UserId = user,
                PermissionKey = Permissions.BookingsCancel,
                Effect = PermissionEffect.Revoke,
            });
            await db.SaveChangesAsync();
        }, SeedIds.TenantB);

        (await client.PostAsync($"/api/v1/bookings/{draft.Id}/cancel", null)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await client.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await (await client.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>()).Permissions.ShouldNotContain(Permissions.BookingsCancel);
    }

    [Fact]
    public async Task A_grant_added_in_the_database_widens_the_scope_for_the_same_token()
    {
        const string user = SeedIds.AgencyStaffB;
        using var client = await factory.ClientForAsync(user);
        var (_, before) = await ApiHelpers.ListIdsAsync(client);

        await WithDbAsync(async db =>
        {
            db.UserPermissions.Add(new UserPermissionEntity
            {
                TenantId = SeedIds.TenantB,
                UserId = user,
                PermissionKey = Permissions.BookingsViewAllAgency,
                Effect = PermissionEffect.Grant,
            });
            await db.SaveChangesAsync();
        }, SeedIds.TenantB);

        var (_, after) = await ApiHelpers.ListIdsAsync(client);
        after.Count.ShouldBeGreaterThan(before.Count);
        before.ShouldBeSubsetOf(after);
    }

    [Fact]
    public async Task Editing_a_role_default_changes_every_holder_of_that_role_in_that_tenant_immediately()
    {
        using var client = await factory.ClientForAsync(SeedIds.CorporateStaffB);
        (await client.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.OK);

        await WithDbAsync(
            async db => await db.RolePermissions
                .IgnoreQueryFilters()
                .Where(rp => rp.TenantId == SeedIds.TenantB && rp.RoleKey == RoleKeys.CorporateStaff && rp.PermissionKey == Permissions.BookingsRead)
                .ExecuteDeleteAsync(),
            SeedIds.TenantB);

        (await client.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Deactivating_a_user_removes_all_access_even_though_the_token_is_still_valid()
    {
        using var client = await factory.ClientForAsync(SeedIds.InternalAdminB);
        (await client.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.OK);

        await WithDbAsync(
            async db => await db.Users
                .IgnoreQueryFilters()
                .Where(u => u.Id == SeedIds.InternalAdminB)
                .ExecuteUpdateAsync(s => s.SetProperty(u => u.IsActive, false)),
            SeedIds.TenantB);

        (await client.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await (await client.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>()).Permissions.ShouldBeEmpty();
    }

    [Fact]
    public async Task A_role_change_after_creation_keeps_history_in_its_original_scope_and_revokes_old_sessions()
    {
        const string user = SeedIds.AgencyStaffA;
        using var staff = await factory.ClientForAsync(user, freshToken: true);
        var created = await ApiHelpers.CreateBookingAsync(staff);
        created.OwnerRoleFamilyAtCreation.ShouldBe(RoleFamily.Agency);

        // Promote the user into the internal family and revoke the sessions that carry the old role.
        await WithDbAsync(async db => await db.Users
            .IgnoreQueryFilters()
            .Where(u => u.Id == user)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.RoleKey, RoleKeys.InternalStaff).SetProperty(u => u.AgencyId, (string?)null)));
        await factory.Services.GetRequiredService<ITokenVersionStore>().BumpAsync(SeedIds.TenantA, user, CancellationToken.None);

        (await staff.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        using var promoted = await factory.ClientForAsync(user, freshToken: true);
        (await (await promoted.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>()).Family.ShouldBe(RoleFamily.Internal);
        (await promoted.GetAsync($"/api/v1/bookings/{created.Id}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);

        using var agencyAdmin = await factory.ClientForAsync(SeedIds.AgencyAdminA);
        var seen = await (await agencyAdmin.GetAsync($"/api/v1/bookings/{created.Id}")).ReadAsAsync<BookingResponse>();
        seen.OwnerRoleFamilyAtCreation.ShouldBe(RoleFamily.Agency);
        seen.AgencyId.ShouldBe(SeedIds.AgencyA1);

        using var internalAdmin = await factory.ClientForAsync(SeedIds.InternalAdminA);
        (await internalAdmin.GetAsync($"/api/v1/bookings/{created.Id}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }
}
