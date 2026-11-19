using Rbac.Abstractions;
using Rbac.Core.Catalog;
using Rbac.Core.Management;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Management;

public class RoleManagementTests
{
    private static readonly RoleCatalog Catalog = DefaultRoleCatalog.Create();

    private static ManagementActor Actor(string roleKey, string? agency = null, string? corporate = null, bool founder = false, string tenant = "t1") =>
        new(Principal.ForStaff("actor", tenant, roleKey, agency, corporate), Catalog.Find(roleKey)!, founder);

    private static ManagedUser Target(string? roleKey, string? agency = null, string? corporate = null, bool founder = false, string tenant = "t1", string id = "target", PrincipalKind kind = PrincipalKind.Staff) =>
        new(id, tenant, kind, roleKey, agency, corporate, founder);

    private static ManagementDecision Evaluate(ManagementActor actor, ManagementRequest request) =>
        new RoleManagementResolverFixture().For(actor.Principal).Evaluate(actor, request, Catalog);

    private sealed class RoleManagementResolverFixture
    {
        private readonly RoleManagementResolver _resolver = new(
            Catalog,
            RoleManagementRegistry.Create()
                .ForFamily(RoleFamily.System, new CrossAccountRoleManagement())
                .ForFamily(RoleFamily.Finance, new DenyAllRoleManagement())
                .ForFamily(RoleFamily.Internal, new CrossAccountRoleManagement())
                .ForFamily(RoleFamily.Corporate, new AccountRoleManagement())
                .ForFamily(RoleFamily.Agency, new AccountRoleManagement())
                .ForFamily(RoleFamily.Viewer, new DenyAllRoleManagement())
                .Build());

        public IRoleManagementStrategy For(Principal principal) => _resolver.StrategyFor(principal);
    }

    [Fact]
    public void Privilege_follows_the_creation_graph_and_never_includes_the_role_itself()
    {
        RolePrivilege.Reachable(Catalog, RoleKeys.AgencyAdmin).ShouldBe([RoleKeys.AgencyStaff]);
        RolePrivilege.Reachable(Catalog, RoleKeys.AgencyStaff).ShouldBeEmpty();
        RolePrivilege.Reachable(Catalog, RoleKeys.SystemAdmin).Count.ShouldBe(8);
        RolePrivilege.Reachable(Catalog, RoleKeys.SystemAdmin).ShouldNotContain(RoleKeys.SystemAdmin);
        RolePrivilege.Reachable(Catalog, RoleKeys.InternalAdmin).ShouldBe(
            [RoleKeys.InternalStaff, RoleKeys.CorporateAdmin, RoleKeys.AgencyAdmin, RoleKeys.ReportViewer, RoleKeys.CorporateStaff, RoleKeys.AgencyStaff],
            ignoreOrder: true);
        RolePrivilege.Reachable(Catalog, "not-a-role").ShouldBeEmpty();
    }

    [Fact]
    public void Peers_and_higher_roles_are_never_outranked_and_customers_sit_below_internal_and_system()
    {
        var agencyAdmin = Catalog.Find(RoleKeys.AgencyAdmin)!;
        var internalAdmin = Catalog.Find(RoleKeys.InternalAdmin)!;

        RolePrivilege.Outranks(Catalog, agencyAdmin, PrincipalKind.Staff, RoleKeys.AgencyAdmin).ShouldBeFalse("a peer");
        RolePrivilege.Outranks(Catalog, agencyAdmin, PrincipalKind.Staff, RoleKeys.InternalAdmin).ShouldBeFalse("higher");
        RolePrivilege.Outranks(Catalog, agencyAdmin, PrincipalKind.Staff, RoleKeys.AgencyStaff).ShouldBeTrue();
        RolePrivilege.Outranks(Catalog, internalAdmin, PrincipalKind.Staff, RoleKeys.SystemAdmin).ShouldBeFalse();
        RolePrivilege.Outranks(Catalog, internalAdmin, PrincipalKind.Customer, null).ShouldBeTrue();
        RolePrivilege.Outranks(Catalog, agencyAdmin, PrincipalKind.Customer, null).ShouldBeFalse();
    }

    [Fact]
    public void The_founding_admin_may_create_admins_in_their_own_account_but_other_admins_create_staff_only()
    {
        var founder = Actor(RoleKeys.AgencyAdmin, agency: "ag1", founder: true);
        var other = Actor(RoleKeys.AgencyAdmin, agency: "ag1");
        var admin = Catalog.Find(RoleKeys.AgencyAdmin)!;
        var staff = Catalog.Find(RoleKeys.AgencyStaff)!;

        Evaluate(founder, new(ManagementOperation.Create, NewRole: admin, AgencyId: "ag1")).Allowed.ShouldBeTrue();
        Evaluate(other, new(ManagementOperation.Create, NewRole: admin, AgencyId: "ag1")).Allowed.ShouldBeFalse();
        Evaluate(other, new(ManagementOperation.Create, NewRole: staff, AgencyId: "ag1")).Allowed.ShouldBeTrue();
    }

    [Fact]
    public void Account_admins_can_only_create_inside_their_own_account()
    {
        var founder = Actor(RoleKeys.AgencyAdmin, agency: "ag1", founder: true);
        var staff = Catalog.Find(RoleKeys.AgencyStaff)!;

        Evaluate(founder, new(ManagementOperation.Create, NewRole: staff, AgencyId: "ag2")).Allowed.ShouldBeFalse();
        Evaluate(founder, new(ManagementOperation.Create, NewRole: staff, AgencyId: null)).Allowed.ShouldBeFalse();
    }

    [Fact]
    public void An_account_admin_cannot_create_roles_outside_their_creatable_list_or_in_another_family()
    {
        var founder = Actor(RoleKeys.AgencyAdmin, agency: "ag1", founder: true);

        Evaluate(founder, new(ManagementOperation.Create, NewRole: Catalog.Find(RoleKeys.InternalStaff)!)).Allowed.ShouldBeFalse();
        Evaluate(founder, new(ManagementOperation.Create, NewRole: Catalog.Find(RoleKeys.CorporateStaff)!, CorporateId: "co1")).Allowed.ShouldBeFalse();
    }

    [Fact]
    public void Nobody_inside_an_account_can_delete_or_demote_the_founding_admin()
    {
        var founderTarget = Target(RoleKeys.AgencyAdmin, agency: "ag1", founder: true);

        foreach (var actor in new[] { Actor(RoleKeys.AgencyAdmin, agency: "ag1"), Actor(RoleKeys.AgencyAdmin, agency: "ag1", founder: true) })
        {
            Evaluate(actor, new(ManagementOperation.Delete, founderTarget)).Allowed.ShouldBeFalse();
            Evaluate(actor, new(ManagementOperation.ChangeRole, founderTarget, Catalog.Find(RoleKeys.AgencyStaff)!, AgencyId: "ag1")).Allowed.ShouldBeFalse();
        }
    }

    [Fact]
    public void Internal_and_system_admins_can_manage_the_founding_admin_of_any_account_in_their_tenant()
    {
        var founderTarget = Target(RoleKeys.AgencyAdmin, agency: "ag1", founder: true);

        Evaluate(Actor(RoleKeys.InternalAdmin), new(ManagementOperation.Delete, founderTarget)).Allowed.ShouldBeTrue();
        Evaluate(Actor(RoleKeys.SystemAdmin), new(ManagementOperation.Delete, founderTarget)).Allowed.ShouldBeTrue();
        Evaluate(Actor(RoleKeys.InternalAdmin), new(ManagementOperation.ChangeRole, founderTarget, Catalog.Find(RoleKeys.AgencyStaff)!, AgencyId: "ag1")).Allowed.ShouldBeTrue();
    }

    [Fact]
    public void The_founding_admin_manages_the_other_admins_of_the_account_but_a_plain_admin_manages_staff_only()
    {
        var peerAdmin = Target(RoleKeys.AgencyAdmin, agency: "ag1");
        var staff = Target(RoleKeys.AgencyStaff, agency: "ag1");
        var founder = Actor(RoleKeys.AgencyAdmin, agency: "ag1", founder: true);
        var plain = Actor(RoleKeys.AgencyAdmin, agency: "ag1");

        Evaluate(founder, new(ManagementOperation.Delete, peerAdmin)).Allowed.ShouldBeTrue();
        Evaluate(plain, new(ManagementOperation.Delete, peerAdmin)).Allowed.ShouldBeFalse();
        Evaluate(plain, new(ManagementOperation.Delete, staff)).Allowed.ShouldBeTrue();
        Evaluate(plain, new(ManagementOperation.EditPermissions, staff)).Allowed.ShouldBeTrue();
    }

    [Fact]
    public void Nobody_manages_users_of_another_account_or_another_tenant_or_themselves()
    {
        var agencyFounder = Actor(RoleKeys.AgencyAdmin, agency: "ag1", founder: true);
        var system = Actor(RoleKeys.SystemAdmin);

        Evaluate(agencyFounder, new(ManagementOperation.Delete, Target(RoleKeys.AgencyStaff, agency: "ag2"))).Allowed.ShouldBeFalse();
        Evaluate(agencyFounder, new(ManagementOperation.Delete, Target(RoleKeys.AgencyStaff, agency: "ag1", tenant: "t2"))).Allowed.ShouldBeFalse();
        Evaluate(system, new(ManagementOperation.Delete, Target(RoleKeys.AgencyStaff, agency: "ag1", tenant: "t2"))).Allowed.ShouldBeFalse();
        Evaluate(system, new(ManagementOperation.Delete, Target(RoleKeys.AgencyStaff, id: "actor"))).Allowed.ShouldBeFalse();
    }

    [Fact]
    public void A_system_admin_cannot_manage_another_system_admin_and_an_internal_admin_cannot_manage_a_system_admin()
    {
        Evaluate(Actor(RoleKeys.SystemAdmin), new(ManagementOperation.Delete, Target(RoleKeys.SystemAdmin))).Allowed.ShouldBeFalse();
        Evaluate(Actor(RoleKeys.InternalAdmin), new(ManagementOperation.Delete, Target(RoleKeys.SystemAdmin))).Allowed.ShouldBeFalse();
    }

    [Theory]
    [InlineData(RoleKeys.FinanceOfficer)]
    [InlineData(RoleKeys.ReportViewer)]
    [InlineData(RoleKeys.InternalStaff)]
    [InlineData(RoleKeys.AgencyStaff)]
    [InlineData(RoleKeys.CorporateStaff)]
    public void Roles_without_creatable_roles_manage_nobody_even_if_granted_the_permission(string roleKey)
    {
        var actor = Actor(roleKey, agency: "ag1", corporate: "co1");

        Evaluate(actor, new(ManagementOperation.Create, NewRole: Catalog.Find(RoleKeys.AgencyStaff)!, AgencyId: "ag1")).Allowed.ShouldBeFalse();
        Evaluate(actor, new(ManagementOperation.Delete, Target(RoleKeys.AgencyStaff, agency: "ag1"))).Allowed.ShouldBeFalse();
    }

    [Fact]
    public void Customers_and_anonymous_callers_and_unknown_roles_resolve_to_deny_all()
    {
        var resolver = new RoleManagementResolverFixture();

        resolver.For(Principal.ForCustomer("c1", "t1")).Name.ShouldBe(nameof(DenyAllRoleManagement));
        resolver.For(Principal.Anonymous).Name.ShouldBe(nameof(DenyAllRoleManagement));
        resolver.For(Principal.ForStaff("u", "t1", "ghost")).Name.ShouldBe(nameof(DenyAllRoleManagement));
    }

    [Fact]
    public void An_account_admin_without_an_account_manages_nobody()
    {
        var unbound = Actor(RoleKeys.AgencyAdmin, agency: null, founder: true);

        Evaluate(unbound, new(ManagementOperation.Create, NewRole: Catalog.Find(RoleKeys.AgencyStaff)!, AgencyId: null)).Allowed.ShouldBeFalse();
        Evaluate(unbound, new(ManagementOperation.Delete, Target(RoleKeys.AgencyStaff, agency: null))).Allowed.ShouldBeFalse();
    }
}
