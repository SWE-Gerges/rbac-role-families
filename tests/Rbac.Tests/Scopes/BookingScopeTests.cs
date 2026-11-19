using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;
using Rbac.Core.Scopes;
using Rbac.Tests.Support;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Scopes;

public class BookingScopeTests
{
    private static IReadOnlyList<string> Visible(IAccessScopeStrategy<Booking> strategy, Principal principal, params string[] permissions) =>
        ScopeDataset.Visible(ScopeDataset.Query, strategy, principal, PermissionSet.Create(permissions));

    [Fact]
    public void System_scope_sees_every_row_of_its_own_tenant_and_nothing_else()
    {
        Visible(new SystemScope(), Principals.SystemAdmin()).ShouldBe(
            ["b01", "b02", "b03", "b04", "b05", "b06", "b07", "b08", "b09", "b10", "b11", "b12", "b13", "b14"]);

        Visible(new SystemScope(), Principals.SystemAdmin(ScopeDataset.TenantB)).ShouldBe(["b20", "b21", "b22", "b23"]);
    }

    [Fact]
    public void Internal_scope_sees_internal_written_and_guest_bookings_but_not_agency_or_corporate_owned()
    {
        // b13 is a guest booking made through an agency: it belongs to the agency, not to internal staff.
        Visible(new InternalScope(), Principals.InternalStaff()).ShouldBe(["b01", "b02", "b11", "b14"]);
    }

    [Fact]
    public void Agency_admin_sees_the_whole_agency_in_their_tenant_only()
    {
        Visible(new AgencyScope(), Principals.AgencyAdmin()).ShouldBe(["b03", "b04", "b05", "b12", "b13"]);
        Visible(new AgencyScope(), Principals.AgencyAdmin("ag2")).ShouldBe(["b06"]);
    }

    [Fact]
    public void Agency_staff_see_only_their_own_bookings_by_default()
    {
        Visible(new AgencyScope(), Principals.AgencyStaff()).ShouldBe(["b03", "b12"]);
    }

    [Fact]
    public void Agency_staff_with_view_all_permission_see_the_whole_agency()
    {
        Visible(new AgencyScope(), Principals.AgencyStaff(), Permissions.BookingsViewAllAgency)
            .ShouldBe(["b03", "b04", "b05", "b12", "b13"]);
    }

    [Fact]
    public void The_corporate_view_all_permission_does_not_widen_an_agency_scope()
    {
        Visible(new AgencyScope(), Principals.AgencyStaff(), Permissions.BookingsViewAllCorporate).ShouldBe(["b03", "b12"]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Agency_scope_fails_closed_without_an_agency(string? agencyId)
    {
        Visible(new AgencyScope(), Principals.AgencyAdmin(agencyId), Permissions.BookingsViewAllAgency).ShouldBeEmpty();
        Visible(new AgencyScope(), Principals.AgencyStaff(agencyId)).ShouldBeEmpty();
    }

    [Fact]
    public void Corporate_admin_sees_the_whole_corporate_account()
    {
        Visible(new CorporateScope(), Principals.CorporateAdmin()).ShouldBe(["b07", "b08"]);
    }

    [Fact]
    public void Corporate_staff_see_only_their_own_bookings_unless_granted_view_all()
    {
        Visible(new CorporateScope(), Principals.CorporateStaff()).ShouldBe(["b07"]);
        Visible(new CorporateScope(), Principals.CorporateStaff(), Permissions.BookingsViewAllCorporate).ShouldBe(["b07", "b08"]);
    }

    [Fact]
    public void Corporate_scope_fails_closed_without_a_corporate_account()
    {
        Visible(new CorporateScope(), Principals.CorporateAdmin(null), Permissions.BookingsViewAllCorporate).ShouldBeEmpty();
        Visible(new CorporateScope(), Principals.CorporateStaff(null)).ShouldBeEmpty();
    }

    [Fact]
    public void Finance_sees_only_refund_related_bookings_without_reports_view()
    {
        Visible(new FinanceScope(), Principals.Finance()).ShouldBe(["b10", "b11", "b12"]);
    }

    [Fact]
    public void Finance_with_reports_view_sees_the_whole_tenant()
    {
        Visible(new FinanceScope(), Principals.Finance(), Permissions.ReportsView).Count.ShouldBe(14);
    }

    [Fact]
    public void Viewer_scope_never_returns_booking_rows_even_with_every_permission()
    {
        Visible(new ViewerScope(), Principals.Viewer(), [.. Permissions.All]).ShouldBeEmpty();
    }

    [Fact]
    public void Customer_scope_returns_only_the_customers_own_bookings_in_their_tenant()
    {
        Visible(new CustomerScope(), Principals.Customer()).ShouldBe(["b10"]);
        Visible(new CustomerScope(), Principals.Customer(ScopeDataset.TenantB)).ShouldBe(["b22"]);
    }

    [Fact]
    public void No_access_scope_returns_nothing()
    {
        Visible(new NoAccessScope<Booking>(), Principals.SystemAdmin(), [.. Permissions.All]).ShouldBeEmpty();
    }

    [Fact]
    public void Staff_strategies_return_nothing_for_anonymous_and_customer_principals()
    {
        IAccessScopeStrategy<Booking>[] staffStrategies =
            [new SystemScope(), new InternalScope(), new AgencyScope(), new CorporateScope(), new FinanceScope(), new ViewerScope()];

        foreach (var strategy in staffStrategies)
        {
            Visible(strategy, Principal.Anonymous, [.. Permissions.All]).ShouldBeEmpty(strategy.Name);
            Visible(strategy, Principals.Customer(), [.. Permissions.All]).ShouldBeEmpty(strategy.Name);
        }
    }

    [Fact]
    public void Customer_strategy_returns_nothing_for_staff_and_anonymous_principals()
    {
        Visible(new CustomerScope(), Principals.SystemAdmin(), [.. Permissions.All]).ShouldBeEmpty();
        Visible(new CustomerScope(), Principal.Anonymous).ShouldBeEmpty();
    }

    [Fact]
    public void Every_strategy_constrains_the_tenant_even_when_ids_collide_across_tenants()
    {
        // Tenant-2 reuses agency id "ag1", corporate id "co1" and user id "u-customer".
        var tenantB = ScopeDataset.TenantB;
        var principals = new (IAccessScopeStrategy<Booking> Strategy, Principal Principal)[]
        {
            (new AgencyScope(), Principals.Staff("u-agency-admin", RoleKeys.AgencyAdmin, agencyId: "ag1", tenantId: tenantB)),
            (new CorporateScope(), Principals.Staff("u-corp-admin", RoleKeys.CorporateAdmin, corporateId: "co1", tenantId: tenantB)),
            (new InternalScope(), Principals.Staff("u-internal", RoleKeys.InternalStaff, tenantId: tenantB)),
            (new FinanceScope(), Principals.Staff("u-finance", RoleKeys.FinanceOfficer, tenantId: tenantB)),
            (new SystemScope(), Principals.SystemAdmin(tenantB)),
            (new CustomerScope(), Principals.Customer(tenantB)),
        };

        foreach (var (strategy, principal) in principals)
        {
            Visible(strategy, principal, Permissions.ReportsView, Permissions.BookingsViewAllAgency)
                .ShouldAllBe(id => id.StartsWith("b2", StringComparison.Ordinal), strategy.Name);
        }
    }
}
