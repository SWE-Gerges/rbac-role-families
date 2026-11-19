namespace Rbac.Abstractions;

public enum OnBehalfFailure
{
    None,

    /// <summary>The actor does not hold the permission to act on behalf of anyone.</summary>
    MissingPermission,

    /// <summary>The target does not exist or is not visible to the actor, which includes every user of another tenant.</summary>
    NotFound,

    /// <summary>The target is visible but the actor may not act as them (equal or higher privilege, outside the actor's account, deactivated).</summary>
    NotAllowed,
}

/// <summary>The outcome of resolving an on-behalf-of request: the effective principal, or why there is none.</summary>
public sealed record EffectivePrincipalResult(Principal? Principal, OnBehalfFailure Failure, string? Detail = null)
{
    public bool Succeeded => Principal is not null;

    public static EffectivePrincipalResult Success(Principal principal) => new(principal, OnBehalfFailure.None);

    public static EffectivePrincipalResult Fail(OnBehalfFailure failure, string? detail = null) => new(null, failure, detail);
}

/// <summary>
/// Turns an authenticated actor plus the id of another user into the effective principal whose scope and permissions apply.
/// The actor's own permissions are only used to decide whether they may act on behalf of anyone at all.
/// </summary>
public interface IEffectivePrincipalResolver
{
    Task<EffectivePrincipalResult> ResolveAsync(Principal actor, string targetUserId, CancellationToken cancellationToken);
}
