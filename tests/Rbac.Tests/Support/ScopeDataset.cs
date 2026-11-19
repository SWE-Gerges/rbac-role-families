using Rbac.Abstractions;
using Rbac.Core.Bookings;

namespace Rbac.Tests.Support;

/// <summary>A small hand-written dataset that covers every ownership shape the strategies distinguish.</summary>
internal static class ScopeDataset
{
    public const string TenantA = "tenant-1";
    public const string TenantB = "tenant-2";

    public static IReadOnlyList<Booking> Bookings { get; } = Build();

    public static IQueryable<Booking> Query => Bookings.AsQueryable();

    public static Booking Make(
        string id,
        string tenantId,
        string ownerUserId,
        RoleFamily? family,
        string? agencyId = null,
        string? corporateId = null,
        bool guest = false,
        BookingStatus status = BookingStatus.Confirmed,
        BookingType type = BookingType.Hotel,
        decimal amount = 100m) =>
        Booking.Create(
            id,
            new OwnershipStamp(tenantId, ownerUserId, family, agencyId, corporateId),
            guest,
            type,
            status,
            amount,
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));

    public static IReadOnlyList<string> Visible(IQueryable<Booking> query, IAccessScopeStrategy<Booking> strategy, Principal principal, PermissionSet permissions) =>
        query.Where(strategy.Scope(principal, permissions)).Select(b => b.Id).OrderBy(id => id, StringComparer.Ordinal).ToArray();

    private static List<Booking> Build() =>
    [
        Make("b01", TenantA, "u-internal", RoleFamily.Internal),
        Make("b02", TenantA, "guest-1", null, guest: true),
        Make("b03", TenantA, "u-agency-staff", RoleFamily.Agency, agencyId: "ag1"),
        Make("b04", TenantA, "u-agency-admin", RoleFamily.Agency, agencyId: "ag1"),
        Make("b05", TenantA, "u-agency-staff-2", RoleFamily.Agency, agencyId: "ag1"),
        Make("b06", TenantA, "u-agency2-admin", RoleFamily.Agency, agencyId: "ag2"),
        Make("b07", TenantA, "u-corp-staff", RoleFamily.Corporate, corporateId: "co1"),
        Make("b08", TenantA, "u-corp-admin", RoleFamily.Corporate, corporateId: "co1"),
        Make("b09", TenantA, "u-corp2-admin", RoleFamily.Corporate, corporateId: "co2"),
        Make("b10", TenantA, "u-customer", null, status: BookingStatus.RefundRequested),
        Make("b11", TenantA, "u-internal", RoleFamily.Internal, status: BookingStatus.Refunded),
        Make("b12", TenantA, "u-agency-staff", RoleFamily.Agency, agencyId: "ag1", status: BookingStatus.Refunded),
        Make("b13", TenantA, "guest-2", null, agencyId: "ag1", guest: true),
        Make("b14", TenantA, "u-internal", RoleFamily.Internal, status: BookingStatus.Cancelled),
        Make("b20", TenantB, "u-internal", RoleFamily.Internal),
        Make("b21", TenantB, "u-agency-staff", RoleFamily.Agency, agencyId: "ag1"),
        Make("b22", TenantB, "u-customer", null, status: BookingStatus.Refunded),
        Make("b23", TenantB, "u-corp-admin", RoleFamily.Corporate, corporateId: "co1"),
    ];
}
