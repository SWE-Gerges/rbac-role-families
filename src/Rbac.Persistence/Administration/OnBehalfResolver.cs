using Microsoft.EntityFrameworkCore;
using Rbac.Abstractions;
using Rbac.Core.Catalog;
using Rbac.Core.Management;
using Rbac.Core.Users;

namespace Rbac.Persistence.Administration;

/// <summary>
/// Decides whether an actor may act as another user and builds the effective principal. The actor needs
/// <c>users.act-on-behalf</c>, resolved live and directly from the permission store (never through the per-request
/// permissions, which must stay those of the effective user). The target must be visible to the actor, so another tenant's
/// users do not exist for them, and the actor's management strategy must allow acting as them: strictly higher privilege
/// only, never a peer or a higher role, and inside the actor's own account for account-bound roles.
/// </summary>
internal sealed class OnBehalfResolver(
    IPermissionStore permissions,
    IScopedQuery<User> users,
    IRoleCatalog catalog,
    RoleManagementResolver management,
    ManagementSupport support) : IEffectivePrincipalResolver
{
    public async Task<EffectivePrincipalResult> ResolveAsync(Principal actor, string targetUserId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);

        var held = await permissions.GetEffectivePermissionsAsync(actor, cancellationToken);
        if (!held.Has(Permissions.UsersActOnBehalf))
        {
            return EffectivePrincipalResult.Fail(OnBehalfFailure.MissingPermission, $"X-On-Behalf-Of needs the {Permissions.UsersActOnBehalf} permission.");
        }

        var target = await users.ScopedFor(actor, held)
            .AsNoTracking()
            .Where(u => u.Id == targetUserId)
            .FirstOrDefaultAsync(cancellationToken);
        if (target is null)
        {
            return EffectivePrincipalResult.Fail(OnBehalfFailure.NotFound);
        }

        var managementActor = await support.ResolveActorAsync(actor, cancellationToken);
        if (managementActor is null)
        {
            return EffectivePrincipalResult.Fail(OnBehalfFailure.NotAllowed, "Your role cannot act on behalf of other users.");
        }

        var decision = management.StrategyFor(actor).Evaluate(
            managementActor,
            new ManagementRequest(ManagementOperation.ActOnBehalf, ManagementSupport.ToManaged(target)),
            catalog);
        if (!decision.Allowed)
        {
            return EffectivePrincipalResult.Fail(OnBehalfFailure.NotAllowed, decision.Reason);
        }

        if (!target.IsActive)
        {
            return EffectivePrincipalResult.Fail(OnBehalfFailure.NotAllowed, "That user is deactivated.");
        }

        if (target.Kind == PrincipalKind.Customer)
        {
            return EffectivePrincipalResult.Success(Principal.ForCustomer(target.Id, target.TenantId, actor.TokenVersion) with { ActingUser = actor.UserId });
        }

        if (catalog.Find(target.RoleKey) is null)
        {
            return EffectivePrincipalResult.Fail(OnBehalfFailure.NotAllowed, "That user has no valid role.");
        }

        return EffectivePrincipalResult.Success(
            Principal.ForStaff(target.Id, target.TenantId, target.RoleKey!, target.AgencyId, target.CorporateId, actor.TokenVersion)
            with { ActingUser = actor.UserId });
    }
}
