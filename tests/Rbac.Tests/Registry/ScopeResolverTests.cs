using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;
using Rbac.Core.Registry;
using Rbac.Core.Scopes;
using Rbac.Tests.Support;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Registry;

public class ScopeResolverTests
{
    private static readonly RoleCatalog Catalog = DefaultRoleCatalog.Create();

    private static StrategyRegistry<Booking> FullRegistry() => StrategyRegistry<Booking>.Create()
        .ForFamily(RoleFamily.System, new SystemScope())
        .ForFamily(RoleFamily.Finance, new FinanceScope())
        .ForFamily(RoleFamily.Internal, new InternalScope())
        .ForFamily(RoleFamily.Corporate, new CorporateScope())
        .ForFamily(RoleFamily.Agency, new AgencyScope())
        .ForFamily(RoleFamily.Viewer, new ViewerScope())
        .ForCustomers(new CustomerScope())
        .Build();

    private static ScopeResolver<Booking> Resolver(StrategyRegistry<Booking>? registry = null) =>
        new(Catalog, registry ?? FullRegistry());

    [Theory]
    [InlineData(RoleKeys.SystemAdmin, nameof(SystemScope))]
    [InlineData(RoleKeys.FinanceOfficer, nameof(FinanceScope))]
    [InlineData(RoleKeys.InternalAdmin, nameof(InternalScope))]
    [InlineData(RoleKeys.InternalStaff, nameof(InternalScope))]
    [InlineData(RoleKeys.CorporateAdmin, nameof(CorporateScope))]
    [InlineData(RoleKeys.CorporateStaff, nameof(CorporateScope))]
    [InlineData(RoleKeys.AgencyAdmin, nameof(AgencyScope))]
    [InlineData(RoleKeys.AgencyStaff, nameof(AgencyScope))]
    [InlineData(RoleKeys.ReportViewer, nameof(ViewerScope))]
    public void Every_role_resolves_to_the_strategy_of_its_family(string roleKey, string expectedStrategy)
    {
        var principal = Principals.Staff("u-1", roleKey, agencyId: "ag1", corporateId: "co1");

        Resolver().StrategyFor(principal).Name.ShouldBe(expectedStrategy);
    }

    [Fact]
    public void Customers_resolve_to_the_customer_strategy_not_to_a_staff_family()
    {
        Resolver().StrategyFor(Principals.Customer()).Name.ShouldBe(nameof(CustomerScope));
    }

    [Fact]
    public void Anonymous_callers_get_no_access()
    {
        Resolver().StrategyFor(Principal.Anonymous).Name.ShouldBe(nameof(NoAccessScope<Booking>));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-role")]
    [InlineData("SYSTEM-ADMIN")]
    public void An_unknown_role_gets_no_access_instead_of_a_default_role(string roleKey)
    {
        var principal = Principals.Staff("u-1", roleKey);

        Resolver().StrategyFor(principal).Name.ShouldBe(nameof(NoAccessScope<Booking>));
    }

    [Fact]
    public void A_staff_principal_without_a_role_key_gets_no_access()
    {
        var principal = new Principal(PrincipalKind.Staff, "u-1", ScopeDataset.TenantA, null, null, null, 1);

        Resolver().StrategyFor(principal).Name.ShouldBe(nameof(NoAccessScope<Booking>));
    }

    [Fact]
    public void A_family_without_a_registered_strategy_falls_back_to_no_access()
    {
        var registry = StrategyRegistry<Booking>.Create().ForFamily(RoleFamily.System, new SystemScope()).Build();

        var resolver = Resolver(registry);

        resolver.StrategyFor(Principals.SystemAdmin()).Name.ShouldBe(nameof(SystemScope));
        resolver.StrategyFor(Principals.AgencyAdmin()).Name.ShouldBe(nameof(NoAccessScope<Booking>));
    }

    [Fact]
    public void A_family_registered_twice_is_ambiguous_and_falls_back_to_no_access()
    {
        var registry = StrategyRegistry<Booking>.Create()
            .ForFamily(RoleFamily.System, new SystemScope())
            .ForFamily(RoleFamily.System, new InternalScope())
            .Build();

        Resolver(registry).StrategyFor(Principals.SystemAdmin()).Name.ShouldBe(nameof(NoAccessScope<Booking>));
    }

    [Fact]
    public void Resolution_does_not_depend_on_registration_order()
    {
        RoleFamily[] families = [.. Enum.GetValues<RoleFamily>()];
        var strategies = new Dictionary<RoleFamily, IAccessScopeStrategy<Booking>>
        {
            [RoleFamily.System] = new SystemScope(),
            [RoleFamily.Finance] = new FinanceScope(),
            [RoleFamily.Internal] = new InternalScope(),
            [RoleFamily.Corporate] = new CorporateScope(),
            [RoleFamily.Agency] = new AgencyScope(),
            [RoleFamily.Viewer] = new ViewerScope(),
        };

        var random = new Random(20260101);
        for (var round = 0; round < 25; round++)
        {
            var builder = StrategyRegistry<Booking>.Create();
            foreach (var family in families.OrderBy(_ => random.Next()))
            {
                builder.ForFamily(family, strategies[family]);
            }

            var resolver = Resolver(builder.Build());
            foreach (var role in Catalog.Roles)
            {
                var principal = Principals.Staff("u-1", role.Key, agencyId: "ag1", corporateId: "co1");
                resolver.StrategyFor(principal).ShouldBeSameAs(strategies[role.Family]);
            }
        }
    }

    [Fact]
    public void Resolve_returns_the_predicate_of_the_selected_strategy()
    {
        var resolver = Resolver();
        IScopeResolver<Booking> contract = resolver;
        var principal = Principals.AgencyAdmin();

        var ids = ScopeDataset.Query.Where(contract.Resolve(principal, PermissionSet.Empty)).Select(b => b.Id).ToArray();

        ids.ShouldBe(["b03", "b04", "b05", "b12", "b13"], ignoreOrder: true);
    }

    [Fact]
    public void The_scoped_query_applies_the_resolved_scope_and_an_optional_narrowing()
    {
        IScopedQuery<Booking> scoped = new ScopedQuery<Booking>(ScopeDataset.Query, Resolver());
        var principal = Principals.AgencyAdmin();

        scoped.ScopedFor(principal, PermissionSet.Empty).Select(b => b.Id).ShouldBe(["b03", "b04", "b05", "b12", "b13"], ignoreOrder: true);
        scoped.ScopedFor(principal, PermissionSet.Empty, b => b.Status == BookingStatus.Refunded).Select(b => b.Id).ShouldBe(["b12"]);
    }
}
