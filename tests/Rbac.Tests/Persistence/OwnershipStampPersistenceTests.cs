using Microsoft.EntityFrameworkCore;
using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;
using Rbac.Persistence;
using Rbac.Persistence.Seeding;
using Rbac.Tests.Support;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Persistence;

public class OwnershipStampPersistenceTests
{
    private static async Task<IReadOnlyList<string>> VisibleTo(SqliteTestDatabase database, Principal principal)
    {
        var fixture = TestServices.Resolver();
        await using var db = database.CreateContext(principal.TenantId);
        var permissions = await new DbPermissionStore(db).GetEffectivePermissionsAsync(principal, TestContext.Current.CancellationToken);
        return await db.Bookings
            .Where(fixture.Resolver.Resolve(principal, permissions))
            .Select(b => b.Id)
            .ToListAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task A_role_change_after_creation_does_not_move_historical_bookings_between_scopes()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var catalog = DefaultRoleCatalog.Create();
        var agencyStaff = SeedPrincipals.From(SeedPrincipals.User(SeedIds.AgencyStaffA));
        var agencyAdmin = SeedPrincipals.From(SeedPrincipals.User(SeedIds.AgencyAdminA));

        // The agency staff member writes a booking; ownership is stamped at write time.
        string bookingId;
        await using (var db = database.CreateContext(SeedIds.TenantA))
        {
            var stamp = new OwnershipStamper(catalog).Stamp(agencyStaff).Stamp!;
            var booking = Booking.Create("bk-a-history", stamp, false, BookingType.Hotel, BookingStatus.Confirmed, 120m, DateTimeOffset.UnixEpoch);
            db.Bookings.Add(booking);
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
            bookingId = booking.Id;
        }

        (await VisibleTo(database, agencyStaff)).ShouldContain(bookingId);
        (await VisibleTo(database, agencyAdmin)).ShouldContain(bookingId);

        // The same user is later promoted into the internal family.
        await using (var db = database.CreateContext(SeedIds.TenantA))
        {
            await db.Users.Where(u => u.Id == SeedIds.AgencyStaffA)
                .ExecuteUpdateAsync(s => s.SetProperty(u => u.RoleKey, RoleKeys.InternalStaff).SetProperty(u => u.AgencyId, (string?)null), TestContext.Current.CancellationToken);
        }

        var nowInternal = Principal.ForStaff(SeedIds.AgencyStaffA, SeedIds.TenantA, RoleKeys.InternalStaff);
        var internalAdmin = SeedPrincipals.From(SeedPrincipals.User(SeedIds.InternalAdminA));

        (await VisibleTo(database, nowInternal)).ShouldNotContain(bookingId, "the booking was written as agency data and stays there");
        (await VisibleTo(database, internalAdmin)).ShouldNotContain(bookingId);
        (await VisibleTo(database, agencyAdmin)).ShouldContain(bookingId);

        await using var reload = database.CreateContext(SeedIds.TenantA);
        var stored = await reload.Bookings.SingleAsync(b => b.Id == bookingId, TestContext.Current.CancellationToken);
        stored.OwnerRoleFamilyAtCreation.ShouldBe(RoleFamily.Agency);
        stored.AgencyId.ShouldBe(SeedIds.AgencyA1);
        stored.OwnerUserId.ShouldBe(SeedIds.AgencyStaffA);
    }

    [Fact]
    public void Bookings_written_by_the_same_user_after_the_role_change_get_the_new_family()
    {
        var catalog = DefaultRoleCatalog.Create();
        var asAgency = new OwnershipStamper(catalog).Stamp(Principal.ForStaff("u-1", SeedIds.TenantA, RoleKeys.AgencyStaff, SeedIds.AgencyA1)).Stamp!;
        var asInternal = new OwnershipStamper(catalog).Stamp(Principal.ForStaff("u-1", SeedIds.TenantA, RoleKeys.InternalStaff)).Stamp!;

        asAgency.OwnerRoleFamily.ShouldBe(RoleFamily.Agency);
        asInternal.OwnerRoleFamily.ShouldBe(RoleFamily.Internal);
        asInternal.AgencyId.ShouldBeNull();
    }

    [Fact]
    public async Task The_seeded_family_of_each_booking_is_the_owners_family_and_guests_have_none()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(tenantId: null);

        var bookings = await db.Bookings.IgnoreQueryFilters().AsNoTracking().ToListAsync(TestContext.Current.CancellationToken);

        bookings.Where(b => b.OwnerUserId == SeedIds.AgencyStaffA).ShouldAllBe(b => b.OwnerRoleFamilyAtCreation == RoleFamily.Agency && b.AgencyId == SeedIds.AgencyA1);
        bookings.Where(b => b.OwnerUserId == SeedIds.InternalAdminA).ShouldAllBe(b => b.OwnerRoleFamilyAtCreation == RoleFamily.Internal && b.AgencyId == null);
        bookings.Where(b => b.OwnerUserId == SeedIds.CustomerA).ShouldAllBe(b => b.OwnerRoleFamilyAtCreation == null);
        bookings.Where(b => b.IsGuestBooking).ShouldAllBe(b => b.OwnerRoleFamilyAtCreation == null);
    }
}
