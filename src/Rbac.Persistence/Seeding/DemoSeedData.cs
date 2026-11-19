using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;

namespace Rbac.Persistence.Seeding;

/// <summary>A seeded user. <see cref="Grants"/> are per-user permission overrides on top of the role defaults.</summary>
public sealed record SeedUser(
    string Id,
    string TenantId,
    PrincipalKind Kind,
    string? RoleKey,
    string? AgencyId,
    string? CorporateId,
    string DisplayName,
    IReadOnlyList<string> Grants,
    bool IsFoundingAdmin = false);

/// <summary>Stable identifiers used by the seed, the demo requests and the tests.</summary>
public static class SeedIds
{
    public const string TenantA = "tenant-a";
    public const string TenantB = "tenant-b";

    public const string AgencyA1 = "agency-a1";
    public const string AgencyA2 = "agency-a2";
    public const string AgencyB1 = "agency-b1";
    public const string CorporateA1 = "corp-a1";
    public const string CorporateA2 = "corp-a2";
    public const string CorporateB1 = "corp-b1";

    public const string SystemAdminA = "a-system-admin";
    public const string FinanceOfficerA = "a-finance-officer";
    public const string FinanceReportsA = "a-finance-reports";
    public const string InternalAdminA = "a-internal-admin";
    public const string InternalStaffA = "a-internal-staff";
    public const string CorporateAdminA = "a-corporate-admin";
    public const string CorporateAdmin2A = "a-corporate-admin-2";
    public const string CorporateStaffA = "a-corporate-staff";
    public const string CorporateStaffViewAllA = "a-corporate-staff-viewall";
    public const string Corporate2AdminA = "a-corporate2-admin";
    public const string AgencyAdminA = "a-agency-admin";
    public const string AgencyAdmin2A = "a-agency-admin-2";
    public const string AgencyStaffA = "a-agency-staff";
    public const string AgencyStaffViewAllA = "a-agency-staff-viewall";
    public const string Agency2AdminA = "a-agency2-admin";
    public const string ReportViewerA = "a-report-viewer";
    public const string CustomerA = "a-customer";

    public const string SystemAdminB = "b-system-admin";
    public const string FinanceOfficerB = "b-finance-officer";
    public const string InternalAdminB = "b-internal-admin";
    public const string InternalStaffB = "b-internal-staff";
    public const string CorporateAdminB = "b-corporate-admin";
    public const string CorporateStaffB = "b-corporate-staff";
    public const string AgencyAdminB = "b-agency-admin";
    public const string AgencyStaffB = "b-agency-staff";
    public const string ReportViewerB = "b-report-viewer";
    public const string CustomerB = "b-customer";
}

/// <summary>
/// The deterministic demo dataset: two tenants, one user per role in each (plus a few extra users that show
/// per-user overrides and a second agency/corporate account), and 60 bookings across every status and owner shape.
/// </summary>
public static class DemoSeedData
{
    private static readonly DateTimeOffset Epoch = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static readonly BookingStatus[] StatusCycle =
    [
        BookingStatus.Draft,
        BookingStatus.Confirmed,
        BookingStatus.Ticketed,
        BookingStatus.RefundRequested,
        BookingStatus.Cancelled,
        BookingStatus.Refunded,
        BookingStatus.Confirmed,
        BookingStatus.Draft,
    ];

    private static readonly BookingType[] TypeCycle = [BookingType.Hotel, BookingType.Flight, BookingType.Transfer];

    public static IReadOnlyList<(string Id, string Name)> Tenants { get; } =
    [
        (SeedIds.TenantA, "Tenant A"),
        (SeedIds.TenantB, "Tenant B"),
    ];

    public static IReadOnlyList<SeedUser> Users { get; } = BuildUsers();

    private static IReadOnlyList<SeedUser> BuildUsers()
    {
        static SeedUser Staff(string id, string tenant, string role, string? agency = null, string? corporate = null, bool founder = false, params string[] grants) =>
            new(id, tenant, PrincipalKind.Staff, role, agency, corporate, id, grants, founder);

        static SeedUser Customer(string id, string tenant) =>
            new(id, tenant, PrincipalKind.Customer, null, null, null, id, []);

        return
        [
            Staff(SeedIds.SystemAdminA, SeedIds.TenantA, RoleKeys.SystemAdmin),
            Staff(SeedIds.FinanceOfficerA, SeedIds.TenantA, RoleKeys.FinanceOfficer),
            Staff(SeedIds.FinanceReportsA, SeedIds.TenantA, RoleKeys.FinanceOfficer, grants: Permissions.ReportsView),
            Staff(SeedIds.InternalAdminA, SeedIds.TenantA, RoleKeys.InternalAdmin),
            Staff(SeedIds.InternalStaffA, SeedIds.TenantA, RoleKeys.InternalStaff),
            Staff(SeedIds.CorporateAdminA, SeedIds.TenantA, RoleKeys.CorporateAdmin, corporate: SeedIds.CorporateA1, founder: true),
            Staff(SeedIds.CorporateAdmin2A, SeedIds.TenantA, RoleKeys.CorporateAdmin, corporate: SeedIds.CorporateA1),
            Staff(SeedIds.CorporateStaffA, SeedIds.TenantA, RoleKeys.CorporateStaff, corporate: SeedIds.CorporateA1),
            Staff(SeedIds.CorporateStaffViewAllA, SeedIds.TenantA, RoleKeys.CorporateStaff, corporate: SeedIds.CorporateA1, grants: Permissions.BookingsViewAllCorporate),
            Staff(SeedIds.Corporate2AdminA, SeedIds.TenantA, RoleKeys.CorporateAdmin, corporate: SeedIds.CorporateA2, founder: true),
            Staff(SeedIds.AgencyAdminA, SeedIds.TenantA, RoleKeys.AgencyAdmin, agency: SeedIds.AgencyA1, founder: true),
            Staff(SeedIds.AgencyAdmin2A, SeedIds.TenantA, RoleKeys.AgencyAdmin, agency: SeedIds.AgencyA1),
            Staff(SeedIds.AgencyStaffA, SeedIds.TenantA, RoleKeys.AgencyStaff, agency: SeedIds.AgencyA1),
            Staff(SeedIds.AgencyStaffViewAllA, SeedIds.TenantA, RoleKeys.AgencyStaff, agency: SeedIds.AgencyA1, grants: Permissions.BookingsViewAllAgency),
            Staff(SeedIds.Agency2AdminA, SeedIds.TenantA, RoleKeys.AgencyAdmin, agency: SeedIds.AgencyA2, founder: true),
            Staff(SeedIds.ReportViewerA, SeedIds.TenantA, RoleKeys.ReportViewer),
            Customer(SeedIds.CustomerA, SeedIds.TenantA),

            Staff(SeedIds.SystemAdminB, SeedIds.TenantB, RoleKeys.SystemAdmin),
            Staff(SeedIds.FinanceOfficerB, SeedIds.TenantB, RoleKeys.FinanceOfficer),
            Staff(SeedIds.InternalAdminB, SeedIds.TenantB, RoleKeys.InternalAdmin),
            Staff(SeedIds.InternalStaffB, SeedIds.TenantB, RoleKeys.InternalStaff),
            Staff(SeedIds.CorporateAdminB, SeedIds.TenantB, RoleKeys.CorporateAdmin, corporate: SeedIds.CorporateB1, founder: true),
            Staff(SeedIds.CorporateStaffB, SeedIds.TenantB, RoleKeys.CorporateStaff, corporate: SeedIds.CorporateB1),
            Staff(SeedIds.AgencyAdminB, SeedIds.TenantB, RoleKeys.AgencyAdmin, agency: SeedIds.AgencyB1, founder: true),
            Staff(SeedIds.AgencyStaffB, SeedIds.TenantB, RoleKeys.AgencyStaff, agency: SeedIds.AgencyB1),
            Staff(SeedIds.ReportViewerB, SeedIds.TenantB, RoleKeys.ReportViewer),
            Customer(SeedIds.CustomerB, SeedIds.TenantB),
        ];
    }

    /// <summary>
    /// The seeded bookings. Ownership is stamped from each owner exactly as the write path would stamp it,
    /// so the family stored on a booking is the owner's family at seed time.
    /// </summary>
    public static IReadOnlyList<Booking> CreateBookings(IRoleCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(catalog);

        var stamper = new OwnershipStamper(catalog);
        var usersById = Users.ToDictionary(u => u.Id, StringComparer.Ordinal);
        var bookings = new List<Booking>();

        void Add(string tenantPrefix, string tenantId, string owner, int count, string? guestAgencyId = null)
        {
            for (var i = 0; i < count; i++)
            {
                var sequence = bookings.Count(b => b.TenantId == tenantId) + 1;
                var status = StatusCycle[(sequence - 1) % StatusCycle.Length];
                var type = TypeCycle[(sequence - 1) % TypeCycle.Length];
                var amount = 50m + (25m * sequence);
                var createdAt = Epoch.AddHours(bookings.Count);
                var id = $"bk-{tenantPrefix}-{sequence:000}";

                OwnershipStamp stamp;
                var isGuest = owner.StartsWith("guest-", StringComparison.Ordinal);
                if (isGuest)
                {
                    stamp = new OwnershipStamp(tenantId, owner, null, guestAgencyId, null);
                }
                else
                {
                    var user = usersById[owner];
                    var principal = user.Kind == PrincipalKind.Customer
                        ? Principal.ForCustomer(user.Id, user.TenantId)
                        : Principal.ForStaff(user.Id, user.TenantId, user.RoleKey!, user.AgencyId, user.CorporateId);
                    stamp = stamper.Stamp(principal).Stamp
                        ?? throw new InvalidOperationException($"Seed user '{owner}' cannot own bookings.");
                }

                bookings.Add(Booking.Create(id, stamp, isGuest, type, status, amount, createdAt));
            }
        }

        Add("a", SeedIds.TenantA, SeedIds.SystemAdminA, 3);
        Add("a", SeedIds.TenantA, SeedIds.InternalAdminA, 4);
        Add("a", SeedIds.TenantA, SeedIds.InternalStaffA, 5);
        Add("a", SeedIds.TenantA, "guest-a-1", 2);
        Add("a", SeedIds.TenantA, "guest-a-2", 2);
        Add("a", SeedIds.TenantA, "guest-a-3", 2, guestAgencyId: SeedIds.AgencyA1);
        Add("a", SeedIds.TenantA, SeedIds.FinanceOfficerA, 1);
        Add("a", SeedIds.TenantA, SeedIds.AgencyAdminA, 4);
        Add("a", SeedIds.TenantA, SeedIds.AgencyStaffA, 4);
        Add("a", SeedIds.TenantA, SeedIds.AgencyStaffViewAllA, 3);
        Add("a", SeedIds.TenantA, SeedIds.Agency2AdminA, 3);
        Add("a", SeedIds.TenantA, SeedIds.CorporateAdminA, 3);
        Add("a", SeedIds.TenantA, SeedIds.CorporateStaffA, 3);
        Add("a", SeedIds.TenantA, SeedIds.CorporateStaffViewAllA, 3);
        Add("a", SeedIds.TenantA, SeedIds.Corporate2AdminA, 2);
        Add("a", SeedIds.TenantA, SeedIds.CustomerA, 4);

        Add("b", SeedIds.TenantB, SeedIds.SystemAdminB, 2);
        Add("b", SeedIds.TenantB, SeedIds.InternalStaffB, 2);
        Add("b", SeedIds.TenantB, "guest-b-1", 1);
        Add("b", SeedIds.TenantB, SeedIds.AgencyAdminB, 2);
        Add("b", SeedIds.TenantB, SeedIds.AgencyStaffB, 1);
        Add("b", SeedIds.TenantB, SeedIds.CorporateAdminB, 2);
        Add("b", SeedIds.TenantB, SeedIds.CustomerB, 2);

        return bookings;
    }
}
