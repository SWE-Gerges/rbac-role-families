using Rbac.Abstractions;

namespace Rbac.Core.Management;

internal static class ManagementRules
{
    /// <summary>A role may be assigned when it is created directly by the actor's role or reachable through the creation graph.</summary>
    public static bool CanAssign(IRoleCatalog catalog, RoleDefinition actorRole, RoleDefinition newRole) =>
        actorRole.CreatableRoleKeys.Contains(newRole.Key) || RolePrivilege.Reachable(catalog, actorRole.Key).Contains(newRole.Key);

    public static bool SameTenant(ManagementActor actor, ManagedUser target) => target.TenantId == actor.Principal.TenantId;

    public static bool IsSelf(ManagementActor actor, ManagedUser target) => target.Id == actor.Principal.UserId;
}

/// <summary>
/// System and internal admins act across the accounts of their tenant and never across tenants. What they may do to a user
/// is bounded only by the creation graph: they outrank everything they can (transitively) create.
/// </summary>
public sealed class CrossAccountRoleManagement : IRoleManagementStrategy
{
    public string Name => nameof(CrossAccountRoleManagement);

    public ManagementDecision Evaluate(ManagementActor actor, ManagementRequest request, IRoleCatalog catalog)
    {
        switch (request.Operation)
        {
            case ManagementOperation.Create:
                return request.NewRole is { } created && actor.Role.CreatableRoleKeys.Contains(created.Key)
                    ? ManagementDecision.Allow
                    : ManagementDecision.Deny("Your role cannot create that role.");

            case ManagementOperation.ChangeRole:
                var manage = CanManage(actor, request.Target!, catalog);
                if (!manage.Allowed)
                {
                    return manage;
                }

                return request.NewRole is { } assigned && ManagementRules.CanAssign(catalog, actor.Role, assigned)
                    ? ManagementDecision.Allow
                    : ManagementDecision.Deny("Your role cannot assign that role.");

            default:
                return CanManage(actor, request.Target!, catalog);
        }
    }

    private static ManagementDecision CanManage(ManagementActor actor, ManagedUser target, IRoleCatalog catalog)
    {
        if (!ManagementRules.SameTenant(actor, target))
        {
            return ManagementDecision.Deny("Users of another tenant cannot be managed.");
        }

        if (ManagementRules.IsSelf(actor, target))
        {
            return ManagementDecision.Deny("You cannot manage your own account.");
        }

        return RolePrivilege.Outranks(catalog, actor.Role, target.Kind, target.RoleKey)
            ? ManagementDecision.Allow
            : ManagementDecision.Deny("Your role does not outrank that user's role.");
    }
}

/// <summary>
/// Agency and corporate admins manage their own account only. Each account has one founding admin: only the founding
/// admin may create or promote further admins, other admins manage staff only, and nobody inside the account can
/// delete or demote the founding admin.
/// </summary>
public sealed class AccountRoleManagement : IRoleManagementStrategy
{
    public string Name => nameof(AccountRoleManagement);

    public ManagementDecision Evaluate(ManagementActor actor, ManagementRequest request, IRoleCatalog catalog)
    {
        var accountId = AccountOf(actor.Principal, actor.Role.Family);
        if (string.IsNullOrWhiteSpace(accountId))
        {
            return ManagementDecision.Deny("You are not bound to an account.");
        }

        switch (request.Operation)
        {
            case ManagementOperation.Create:
                return Create(actor, request, accountId);

            case ManagementOperation.ChangeRole:
                var manage = CanManage(actor, request.Target!, accountId, catalog, allowFounderOverPeers: true);
                if (!manage.Allowed)
                {
                    return manage;
                }

                var assigned = request.NewRole;
                if (assigned is null || assigned.Family != actor.Role.Family || !ManagementRules.CanAssign(catalog, actor.Role, assigned))
                {
                    return ManagementDecision.Deny("Your role cannot assign that role.");
                }

                return AdminTierAllowed(actor, assigned);

            case ManagementOperation.ActOnBehalf:
                return CanManage(actor, request.Target!, accountId, catalog, allowFounderOverPeers: false);

            default:
                return CanManage(actor, request.Target!, accountId, catalog, allowFounderOverPeers: true);
        }
    }

    private static string? AccountOf(Principal principal, RoleFamily family) =>
        family == RoleFamily.Agency ? principal.AgencyId : principal.CorporateId;

    private static string? AccountOf(ManagedUser user, RoleFamily family) =>
        family == RoleFamily.Agency ? user.AgencyId : user.CorporateId;

    private static ManagementDecision Create(ManagementActor actor, ManagementRequest request, string accountId)
    {
        if (request.NewRole is not { } created || !actor.Role.CreatableRoleKeys.Contains(created.Key) || created.Family != actor.Role.Family)
        {
            return ManagementDecision.Deny("Your role cannot create that role.");
        }

        var requested = created.Family == RoleFamily.Agency ? request.AgencyId : request.CorporateId;
        if (requested != accountId)
        {
            return ManagementDecision.Deny("Users can only be created inside your own account.");
        }

        return AdminTierAllowed(actor, created);
    }

    private static ManagementDecision AdminTierAllowed(ManagementActor actor, RoleDefinition newRole) =>
        newRole.IsAdmin && !actor.IsFoundingAdmin
            ? ManagementDecision.Deny("Only the founding admin of the account can create or promote admins.")
            : ManagementDecision.Allow;

    private static ManagementDecision CanManage(
        ManagementActor actor, ManagedUser target, string accountId, IRoleCatalog catalog, bool allowFounderOverPeers)
    {
        if (!ManagementRules.SameTenant(actor, target) || AccountOf(target, actor.Role.Family) != accountId)
        {
            return ManagementDecision.Deny("That user is outside your account.");
        }

        if (ManagementRules.IsSelf(actor, target))
        {
            return ManagementDecision.Deny("You cannot manage your own account.");
        }

        if (target.IsFoundingAdmin)
        {
            return ManagementDecision.Deny("The founding admin of an account can only be managed by internal or system admins.");
        }

        if (RolePrivilege.Outranks(catalog, actor.Role, target.Kind, target.RoleKey))
        {
            return ManagementDecision.Allow;
        }

        // A founding admin also manages the other admins of the account, which are peers in the creation graph.
        var targetRole = catalog.Find(target.RoleKey);
        return allowFounderOverPeers && actor.IsFoundingAdmin && targetRole is { IsAdmin: true } && targetRole.Family == actor.Role.Family
            ? ManagementDecision.Allow
            : ManagementDecision.Deny("Your role does not outrank that user's role.");
    }
}

/// <summary>Families that manage nobody (finance, viewers) and the fail-closed fallback.</summary>
public sealed class DenyAllRoleManagement : IRoleManagementStrategy
{
    public string Name => nameof(DenyAllRoleManagement);

    public ManagementDecision Evaluate(ManagementActor actor, ManagementRequest request, IRoleCatalog catalog) =>
        ManagementDecision.Deny("Your role cannot manage users.");
}
