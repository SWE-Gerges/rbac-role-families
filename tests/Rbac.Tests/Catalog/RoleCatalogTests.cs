using Rbac.Abstractions;
using Rbac.Core;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Catalog;

public class RoleCatalogTests
{
    private static readonly RoleCatalog Catalog = DefaultRoleCatalog.Create();

    [Fact]
    public void The_default_catalog_defines_the_nine_documented_roles_with_unique_keys()
    {
        Catalog.Roles.Select(r => r.Key).ShouldBe(
            [
                RoleKeys.SystemAdmin,
                RoleKeys.FinanceOfficer,
                RoleKeys.InternalAdmin,
                RoleKeys.InternalStaff,
                RoleKeys.CorporateAdmin,
                RoleKeys.CorporateStaff,
                RoleKeys.AgencyAdmin,
                RoleKeys.AgencyStaff,
                RoleKeys.ReportViewer,
            ]);
    }

    [Fact]
    public void Every_family_has_at_least_one_role_and_customers_are_not_a_family()
    {
        foreach (var family in Enum.GetValues<RoleFamily>())
        {
            Catalog.Roles.ShouldContain(r => r.Family == family, family.ToString());
        }

        Enum.GetNames<RoleFamily>().ShouldNotContain("Customer");
        Enum.GetNames<RoleFamily>().ShouldNotContain("Anonymous");
    }

    [Fact]
    public void Role_family_is_the_only_axis_of_membership_for_staff()
    {
        Catalog.Find(RoleKeys.AgencyStaff)!.Family.ShouldBe(RoleFamily.Agency);
        Catalog.Find(RoleKeys.ReportViewer)!.Family.ShouldBe(RoleFamily.Viewer);
    }

    [Fact]
    public void Lookup_is_exact_and_unknown_keys_return_null()
    {
        Catalog.Find("AGENCY-ADMIN").ShouldBeNull();
        Catalog.Find("customer").ShouldBeNull();
        Catalog.Find(null).ShouldBeNull();
        Catalog.Find(string.Empty).ShouldBeNull();
    }

    [Fact]
    public void Default_permissions_only_use_known_permission_strings()
    {
        foreach (var role in Catalog.Roles)
        {
            role.DefaultPermissions.ShouldBeSubsetOf(Permissions.All, role.Key);
        }
    }

    [Fact]
    public void Creatable_role_keys_all_exist_in_the_catalog()
    {
        var keys = Catalog.Roles.Select(r => r.Key).ToHashSet();

        foreach (var role in Catalog.Roles)
        {
            role.CreatableRoleKeys.ShouldBeSubsetOf(keys, role.Key);
        }
    }

    [Fact]
    public void A_catalog_can_be_rebuilt_from_its_own_definitions()
    {
        var rebuilt = RoleCatalog.FromDefinitions(Catalog.Roles);

        rebuilt.Roles.ShouldBe(Catalog.Roles);
        rebuilt.Find(RoleKeys.SystemAdmin).ShouldBeSameAs(Catalog.Find(RoleKeys.SystemAdmin));
    }

    [Fact]
    public void Core_and_abstractions_do_not_depend_on_a_database_or_web_framework()
    {
        string[] forbidden = ["Microsoft.EntityFrameworkCore", "Npgsql", "Microsoft.AspNetCore"];
        var assemblies = new[] { typeof(Booking).Assembly, typeof(Principal).Assembly };

        foreach (var assembly in assemblies)
        {
            var references = assembly.GetReferencedAssemblies().Select(a => a.Name ?? string.Empty).ToArray();
            foreach (var name in forbidden)
            {
                references.ShouldNotContain(r => r.StartsWith(name, StringComparison.Ordinal), $"{assembly.GetName().Name} -> {name}");
            }
        }
    }
}
