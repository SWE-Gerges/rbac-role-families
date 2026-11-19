using Rbac.Abstractions;
using Rbac.Core.Catalog;
using Rbac.Core.Management;
using Rbac.Core.Registry;
using Rbac.Core.Users;
using Rbac.Core.Validation;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Management;

public class UserScopeTests
{
    private static readonly RoleCatalog Catalog = DefaultRoleCatalog.Create();

    private static User U(string id, string tenant, string? role, string? agency = null, string? corporate = null, PrincipalKind kind = PrincipalKind.Staff) =>
        new() { Id = id, TenantId = tenant, Handle = id, DisplayName = id, Kind = kind, RoleKey = role, AgencyId = agency, CorporateId = corporate };

    private static readonly User[] Users =
    [
        U("sys", "t1", RoleKeys.SystemAdmin),
        U("int", "t1", RoleKeys.InternalAdmin),
        U("fin", "t1", RoleKeys.FinanceOfficer),
        U("ag1-admin", "t1", RoleKeys.AgencyAdmin, agency: "ag1"),
        U("ag1-staff", "t1", RoleKeys.AgencyStaff, agency: "ag1"),
        U("ag2-admin", "t1", RoleKeys.AgencyAdmin, agency: "ag2"),
        U("co1-admin", "t1", RoleKeys.CorporateAdmin, corporate: "co1"),
        U("cust", "t1", null, kind: PrincipalKind.Customer),
        U("other-sys", "t2", RoleKeys.SystemAdmin),
        U("other-ag1", "t2", RoleKeys.AgencyStaff, agency: "ag1"),
    ];

    private static string[] Visible(IAccessScopeStrategy<User> strategy, Principal principal) =>
        [.. Users.AsQueryable().Where(strategy.Scope(principal, PermissionSet.Empty)).Select(u => u.Id).Order(StringComparer.Ordinal)];

    [Fact]
    public void System_sees_every_user_of_its_tenant_only()
    {
        Visible(new SystemUserScope(), Principal.ForStaff("sys", "t1", RoleKeys.SystemAdmin))
            .ShouldBe(["ag1-admin", "ag1-staff", "ag2-admin", "co1-admin", "cust", "fin", "int", "sys"]);
    }

    [Fact]
    public void Internal_sees_everyone_in_the_tenant_except_system_family_users()
    {
        Visible(new InternalUserScope(Catalog), Principal.ForStaff("int", "t1", RoleKeys.InternalAdmin))
            .ShouldBe(["ag1-admin", "ag1-staff", "ag2-admin", "co1-admin", "cust", "fin", "int"]);
    }

    [Fact]
    public void Account_scopes_see_their_own_account_in_their_own_tenant_and_fail_closed_without_one()
    {
        Visible(new AgencyUserScope(), Principal.ForStaff("ag1-admin", "t1", RoleKeys.AgencyAdmin, agencyId: "ag1")).ShouldBe(["ag1-admin", "ag1-staff"]);
        Visible(new AgencyUserScope(), Principal.ForStaff("ag1-admin", "t1", RoleKeys.AgencyAdmin)).ShouldBeEmpty();
        Visible(new CorporateUserScope(), Principal.ForStaff("co1-admin", "t1", RoleKeys.CorporateAdmin, corporateId: "co1")).ShouldBe(["co1-admin"]);
        Visible(new CorporateUserScope(), Principal.ForStaff("x", "t1", RoleKeys.CorporateAdmin)).ShouldBeEmpty();
    }

    [Fact]
    public void Self_scope_sees_only_the_caller_and_denies_anonymous_callers()
    {
        Visible(new SelfUserScope(), Principal.ForStaff("fin", "t1", RoleKeys.FinanceOfficer)).ShouldBe(["fin"]);
        Visible(new SelfUserScope(), Principal.ForCustomer("cust", "t1")).ShouldBe(["cust"]);
        Visible(new SelfUserScope(), Principal.Anonymous).ShouldBeEmpty();
    }

    [Fact]
    public void Staff_scopes_return_nothing_for_customers_and_anonymous_callers()
    {
        IAccessScopeStrategy<User>[] strategies = [new SystemUserScope(), new InternalUserScope(Catalog), new AgencyUserScope(), new CorporateUserScope()];

        foreach (var strategy in strategies)
        {
            Visible(strategy, Principal.Anonymous).ShouldBeEmpty(strategy.Name);
            Visible(strategy, Principal.ForCustomer("cust", "t1")).ShouldBeEmpty(strategy.Name);
        }
    }

    [Fact]
    public void Every_family_has_exactly_one_management_strategy_and_a_missing_one_fails_validation()
    {
        var complete = RoleManagementRegistry.Create()
            .ForFamily(RoleFamily.System, new CrossAccountRoleManagement())
            .ForFamily(RoleFamily.Finance, new DenyAllRoleManagement())
            .ForFamily(RoleFamily.Internal, new CrossAccountRoleManagement())
            .ForFamily(RoleFamily.Corporate, new AccountRoleManagement())
            .ForFamily(RoleFamily.Agency, new AccountRoleManagement())
            .ForFamily(RoleFamily.Viewer, new DenyAllRoleManagement())
            .Build();
        var missingAgency = RoleManagementRegistry.Create()
            .ForFamily(RoleFamily.System, new CrossAccountRoleManagement())
            .Build();
        var duplicated = RoleManagementRegistry.Create()
            .ForFamily(RoleFamily.System, new CrossAccountRoleManagement())
            .ForFamily(RoleFamily.System, new DenyAllRoleManagement())
            .Build();

        RbacConfigurationValidator.Validate(Catalog, [complete]).ShouldBeEmpty();
        RbacConfigurationValidator.Validate(Catalog, [missingAgency]).ShouldContain(p => p.Contains("'Agency'") && p.Contains("RoleManagement"));
        RbacConfigurationValidator.Validate(Catalog, [duplicated]).ShouldContain(p => p.Contains("'System'") && p.Contains("exactly one"));
    }

    [Fact]
    public void Management_resolution_does_not_depend_on_registration_order()
    {
        var random = new Random(7);
        (RoleFamily Family, IRoleManagementStrategy Strategy)[] all =
        [
            (RoleFamily.System, new CrossAccountRoleManagement()),
            (RoleFamily.Finance, new DenyAllRoleManagement()),
            (RoleFamily.Internal, new CrossAccountRoleManagement()),
            (RoleFamily.Corporate, new AccountRoleManagement()),
            (RoleFamily.Agency, new AccountRoleManagement()),
            (RoleFamily.Viewer, new DenyAllRoleManagement()),
        ];

        for (var round = 0; round < 20; round++)
        {
            var builder = RoleManagementRegistry.Create();
            foreach (var (family, strategy) in all.OrderBy(_ => random.Next()))
            {
                builder.ForFamily(family, strategy);
            }

            var resolver = new RoleManagementResolver(Catalog, builder.Build());
            foreach (var role in Catalog.Roles)
            {
                resolver.StrategyFor(Principal.ForStaff("u", "t", role.Key, "a", "c")).ShouldBeSameAs(all.Single(a => a.Family == role.Family).Strategy);
            }
        }
    }
}
