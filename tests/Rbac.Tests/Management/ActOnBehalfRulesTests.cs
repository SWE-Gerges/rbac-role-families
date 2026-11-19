using Rbac.Abstractions;
using Rbac.Core.Catalog;
using Rbac.Core.Management;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Management;

/// <summary>Acting as another user needs strictly higher standing than that user, inside the actor's own tenant and account.</summary>
public class ActOnBehalfRulesTests
{
    private static readonly RoleCatalog Catalog = DefaultRoleCatalog.Create();

    private static readonly RoleManagementResolver Resolver = new(
        Catalog,
        RoleManagementRegistry.Create()
            .ForFamily(RoleFamily.System, new CrossAccountRoleManagement())
            .ForFamily(RoleFamily.Finance, new DenyAllRoleManagement())
            .ForFamily(RoleFamily.Internal, new CrossAccountRoleManagement())
            .ForFamily(RoleFamily.Corporate, new AccountRoleManagement())
            .ForFamily(RoleFamily.Agency, new AccountRoleManagement())
            .ForFamily(RoleFamily.Viewer, new DenyAllRoleManagement())
            .Build());

    private static ManagementActor Actor(string roleKey, string? agency = null, string? corporate = null, bool founder = false, string tenant = "t1") =>
        new(Principal.ForStaff("actor", tenant, roleKey, agency, corporate), Catalog.Find(roleKey)!, founder);

    private static ManagedUser Target(string? roleKey, string? agency = null, string? corporate = null, bool founder = false, string tenant = "t1", string id = "target", PrincipalKind kind = PrincipalKind.Staff) =>
        new(id, tenant, kind, roleKey, agency, corporate, founder);

    private static ManagementDecision ActAs(ManagementActor actor, ManagedUser target) =>
        Resolver.StrategyFor(actor.Principal).Evaluate(actor, new ManagementRequest(ManagementOperation.ActOnBehalf, target), Catalog);

    [Fact]
    public void System_and_internal_admins_can_act_as_anyone_they_outrank_in_their_tenant()
    {
        ActAs(Actor(RoleKeys.SystemAdmin), Target(RoleKeys.AgencyStaff, agency: "ag1")).Allowed.ShouldBeTrue();
        ActAs(Actor(RoleKeys.SystemAdmin), Target(RoleKeys.InternalAdmin)).Allowed.ShouldBeTrue();
        ActAs(Actor(RoleKeys.SystemAdmin), Target(null, kind: PrincipalKind.Customer)).Allowed.ShouldBeTrue();
        ActAs(Actor(RoleKeys.InternalAdmin), Target(RoleKeys.CorporateStaff, corporate: "co1")).Allowed.ShouldBeTrue();
        ActAs(Actor(RoleKeys.InternalAdmin), Target(null, kind: PrincipalKind.Customer)).Allowed.ShouldBeTrue();
    }

    [Fact]
    public void Nobody_can_act_as_themselves_a_peer_or_a_higher_role()
    {
        ActAs(Actor(RoleKeys.SystemAdmin), Target(RoleKeys.SystemAdmin, id: "actor")).Allowed.ShouldBeFalse("self");
        ActAs(Actor(RoleKeys.SystemAdmin), Target(RoleKeys.SystemAdmin)).Allowed.ShouldBeFalse("a peer");
        ActAs(Actor(RoleKeys.InternalAdmin), Target(RoleKeys.InternalAdmin)).Allowed.ShouldBeFalse("a peer");
        ActAs(Actor(RoleKeys.InternalAdmin), Target(RoleKeys.SystemAdmin)).Allowed.ShouldBeFalse("a higher role");
        ActAs(Actor(RoleKeys.AgencyAdmin, agency: "ag1"), Target(RoleKeys.InternalAdmin)).Allowed.ShouldBeFalse("a higher role");
        ActAs(Actor(RoleKeys.AgencyAdmin, agency: "ag1"), Target(null, kind: PrincipalKind.Customer)).Allowed.ShouldBeFalse("customers belong to internal and system staff");
    }

    [Fact]
    public void Another_tenant_is_never_actable()
    {
        ActAs(Actor(RoleKeys.SystemAdmin, tenant: "t1"), Target(RoleKeys.AgencyStaff, agency: "ag1", tenant: "t2")).Allowed.ShouldBeFalse();
        ActAs(Actor(RoleKeys.InternalAdmin, tenant: "t1"), Target(null, tenant: "t2", kind: PrincipalKind.Customer)).Allowed.ShouldBeFalse();
    }

    [Fact]
    public void Account_admins_act_as_staff_of_their_own_account_only_and_the_founder_gets_no_exception_for_peer_admins()
    {
        var founder = Actor(RoleKeys.AgencyAdmin, agency: "ag1", founder: true);
        var plain = Actor(RoleKeys.AgencyAdmin, agency: "ag1");

        ActAs(plain, Target(RoleKeys.AgencyStaff, agency: "ag1")).Allowed.ShouldBeTrue();
        ActAs(plain, Target(RoleKeys.AgencyStaff, agency: "ag2")).Allowed.ShouldBeFalse("another account");
        ActAs(plain, Target(RoleKeys.AgencyAdmin, agency: "ag1", founder: true)).Allowed.ShouldBeFalse("the founding admin");
        ActAs(founder, Target(RoleKeys.AgencyAdmin, agency: "ag1")).Allowed.ShouldBeFalse("a peer admin, even for the founder");
        ActAs(founder, Target(RoleKeys.AgencyStaff, agency: "ag1")).Allowed.ShouldBeTrue();

        // The founder may still manage a peer admin; acting as one is held to a stricter bar.
        Resolver.StrategyFor(founder.Principal)
            .Evaluate(founder, new ManagementRequest(ManagementOperation.Delete, Target(RoleKeys.AgencyAdmin, agency: "ag1")), Catalog)
            .Allowed.ShouldBeTrue();
    }

    [Fact]
    public void Families_that_manage_nobody_cannot_act_as_anyone()
    {
        ActAs(Actor(RoleKeys.FinanceOfficer), Target(RoleKeys.AgencyStaff, agency: "ag1")).Allowed.ShouldBeFalse();
        ActAs(Actor(RoleKeys.ReportViewer), Target(RoleKeys.AgencyStaff, agency: "ag1")).Allowed.ShouldBeFalse();
    }
}
