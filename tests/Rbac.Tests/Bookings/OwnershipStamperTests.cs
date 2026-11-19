using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;
using Rbac.Tests.Support;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Bookings;

public class OwnershipStamperTests
{
    private readonly OwnershipStamper _stamper = new(DefaultRoleCatalog.Create());

    [Fact]
    public void Agency_staff_are_stamped_with_their_tenant_user_family_and_agency()
    {
        var result = _stamper.Stamp(Principals.AgencyStaff("ag7"));

        result.Failure.ShouldBe(StampFailure.None);
        result.Stamp.ShouldBe(new OwnershipStamp(ScopeDataset.TenantA, "u-agency-staff", RoleFamily.Agency, "ag7", null));
    }

    [Fact]
    public void Corporate_staff_are_stamped_with_their_corporate_account()
    {
        var result = _stamper.Stamp(Principals.CorporateStaff("co9"));

        result.Stamp.ShouldBe(new OwnershipStamp(ScopeDataset.TenantA, "u-corp-staff", RoleFamily.Corporate, null, "co9"));
    }

    [Fact]
    public void A_stray_agency_claim_on_another_family_is_not_stamped()
    {
        var principal = Principals.Staff("u-internal", RoleKeys.InternalStaff, agencyId: "ag1", corporateId: "co1");

        _stamper.Stamp(principal).Stamp.ShouldBe(new OwnershipStamp(ScopeDataset.TenantA, "u-internal", RoleFamily.Internal, null, null));
    }

    [Fact]
    public void Customers_are_stamped_without_a_staff_family()
    {
        _stamper.Stamp(Principals.Customer()).Stamp.ShouldBe(new OwnershipStamp(ScopeDataset.TenantA, "u-customer", null, null, null));
    }

    [Fact]
    public void An_agency_principal_without_an_agency_cannot_create_ownable_data()
    {
        _stamper.Stamp(Principals.AgencyStaff(null)).Failure.ShouldBe(StampFailure.MissingAgency);
        _stamper.Stamp(Principals.CorporateStaff(" ")).Failure.ShouldBe(StampFailure.MissingCorporate);
    }

    [Fact]
    public void Anonymous_and_unknown_role_principals_are_rejected()
    {
        _stamper.Stamp(Principal.Anonymous).Failure.ShouldBe(StampFailure.Anonymous);
        _stamper.Stamp(Principals.Staff("u-1", "ghost-role")).Failure.ShouldBe(StampFailure.UnknownRole);
    }

    [Fact]
    public void A_booking_keeps_the_stamp_it_was_written_with()
    {
        var stamp = _stamper.Stamp(Principals.AgencyStaff()).Stamp!;

        var booking = Booking.Create("b-1", stamp, false, BookingType.Flight, BookingStatus.Draft, 10m, DateTimeOffset.UnixEpoch);

        booking.OwnerRoleFamilyAtCreation.ShouldBe(RoleFamily.Agency);
        booking.AgencyId.ShouldBe("ag1");
        booking.OwnerUserId.ShouldBe("u-agency-staff");
    }

    [Theory]
    [InlineData(BookingStatus.Draft, CancelOutcome.Cancelled, BookingStatus.Cancelled)]
    [InlineData(BookingStatus.Confirmed, CancelOutcome.Cancelled, BookingStatus.Cancelled)]
    [InlineData(BookingStatus.Cancelled, CancelOutcome.NotCancellable, BookingStatus.Cancelled)]
    [InlineData(BookingStatus.RefundRequested, CancelOutcome.NotCancellable, BookingStatus.RefundRequested)]
    [InlineData(BookingStatus.Refunded, CancelOutcome.NotCancellable, BookingStatus.Refunded)]
    [InlineData(BookingStatus.Ticketed, CancelOutcome.NotCancellable, BookingStatus.Ticketed)]
    public void Only_draft_and_confirmed_bookings_can_be_cancelled(BookingStatus start, CancelOutcome expected, BookingStatus end)
    {
        var booking = ScopeDataset.Make("b-1", ScopeDataset.TenantA, "u-1", RoleFamily.Internal, status: start);

        booking.Cancel().ShouldBe(expected);
        booking.Status.ShouldBe(end);
    }

    [Fact]
    public void A_booking_requires_a_positive_amount()
    {
        var stamp = new OwnershipStamp(ScopeDataset.TenantA, "u-1", null, null, null);

        Should.Throw<ArgumentOutOfRangeException>(() =>
            Booking.Create("b-1", stamp, false, BookingType.Hotel, BookingStatus.Draft, 0m, DateTimeOffset.UnixEpoch));
    }
}
