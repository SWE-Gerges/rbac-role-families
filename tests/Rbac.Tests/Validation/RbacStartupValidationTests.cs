using Microsoft.Extensions.Logging.Abstractions;
using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;
using Rbac.Core.Registry;
using Rbac.Core.Scopes;
using Rbac.Core.Validation;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Validation;

public class RbacStartupValidationTests
{
    private static StrategyRegistryBuilder<Booking> AllFamilies() => StrategyRegistry<Booking>.Create()
        .ForFamily(RoleFamily.System, new SystemScope())
        .ForFamily(RoleFamily.Finance, new FinanceScope())
        .ForFamily(RoleFamily.Internal, new InternalScope())
        .ForFamily(RoleFamily.Corporate, new CorporateScope())
        .ForFamily(RoleFamily.Agency, new AgencyScope())
        .ForFamily(RoleFamily.Viewer, new ViewerScope());

    private static IReadOnlyList<string> Validate(IRoleCatalog catalog, params IStrategyRegistry[] registries) =>
        RbacConfigurationValidator.Validate(catalog, registries);

    [Fact]
    public void The_default_catalog_with_a_complete_registry_is_valid()
    {
        Validate(DefaultRoleCatalog.Create(), AllFamilies().Build()).ShouldBeEmpty();
    }

    [Fact]
    public void A_role_without_a_family_is_rejected()
    {
        var catalog = RoleCatalog.Create()
            .Role("orphan", default)
            .Build();

        Validate(catalog, AllFamilies().Build())
            .ShouldContain(p => p.Contains("'orphan'") && p.Contains("no valid role family"));
    }

    [Fact]
    public void A_role_with_an_out_of_range_family_is_rejected()
    {
        var catalog = RoleCatalog.Create().Role("odd", (RoleFamily)99).Build();

        Validate(catalog, AllFamilies().Build()).ShouldContain(p => p.Contains("'odd'"));
    }

    [Fact]
    public void A_family_without_a_strategy_is_rejected()
    {
        var registry = StrategyRegistry<Booking>.Create()
            .ForFamily(RoleFamily.System, new SystemScope())
            .Build();

        var problems = Validate(DefaultRoleCatalog.Create(), registry);

        problems.ShouldContain(p => p.Contains("'Agency'") && p.Contains("no strategy"));
        problems.ShouldNotContain(p => p.Contains("'System'"));
    }

    [Fact]
    public void A_family_with_two_strategies_is_rejected()
    {
        var registry = AllFamilies().ForFamily(RoleFamily.Agency, new InternalScope()).Build();

        Validate(DefaultRoleCatalog.Create(), registry)
            .ShouldContain(p => p.Contains("'Agency'") && p.Contains("exactly one"));
    }

    [Fact]
    public void A_strategy_for_an_undefined_family_is_rejected()
    {
        var registry = AllFamilies().ForFamily((RoleFamily)42, new SystemScope()).Build();

        Validate(DefaultRoleCatalog.Create(), registry)
            .ShouldContain(p => p.Contains("undefined family '42'"));
    }

    [Fact]
    public void Two_roles_sharing_a_key_are_rejected()
    {
        var catalog = RoleCatalog.Create()
            .Role("shared", RoleFamily.Agency)
            .Role("shared", RoleFamily.Corporate)
            .Build();

        Validate(catalog, AllFamilies().Build())
            .ShouldContain(p => p.Contains("'shared'") && p.Contains("2 times"));
        catalog.Find("shared").ShouldBeNull("an ambiguous key must never resolve to one of the two roles");
    }

    [Fact]
    public void A_creatable_role_key_that_does_not_exist_is_rejected()
    {
        var catalog = RoleCatalog.Create()
            .Role("boss", RoleFamily.System, r => r.CanCreate("ghost"))
            .Build();

        Validate(catalog, AllFamilies().Build())
            .ShouldContain(p => p.Contains("'boss'") && p.Contains("'ghost'"));
    }

    [Fact]
    public void A_host_without_any_registry_is_rejected()
    {
        Validate(DefaultRoleCatalog.Create()).ShouldContain(p => p.Contains("No strategy registry"));
    }

    [Fact]
    public void Every_problem_is_reported_in_a_single_failure()
    {
        var catalog = RoleCatalog.Create()
            .Role("a", RoleFamily.Agency)
            .Role("a", RoleFamily.Agency)
            .Role("b", default, r => r.CanCreate("ghost"))
            .Build();
        var registry = StrategyRegistry<Booking>.Create().Build();

        Validate(catalog, registry).Count.ShouldBeGreaterThanOrEqualTo(9);
    }

    [Fact]
    public async Task The_hosted_validator_throws_on_start_when_the_configuration_is_invalid()
    {
        var validator = new RbacStartupValidator(
            RoleCatalog.Create().Role("orphan", default).Build(),
            [AllFamilies().Build()],
            NullLogger<RbacStartupValidator>.Instance);

        var exception = await Should.ThrowAsync<RbacConfigurationException>(() => validator.StartAsync(CancellationToken.None));

        exception.Problems.ShouldNotBeEmpty();
        exception.Message.ShouldContain("orphan");
    }

    [Fact]
    public async Task The_hosted_validator_starts_cleanly_for_a_valid_configuration()
    {
        var validator = new RbacStartupValidator(
            DefaultRoleCatalog.Create(),
            [AllFamilies().Build()],
            NullLogger<RbacStartupValidator>.Instance);

        await Should.NotThrowAsync(() => validator.StartAsync(CancellationToken.None));
    }
}
