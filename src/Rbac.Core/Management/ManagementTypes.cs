using Rbac.Abstractions;

namespace Rbac.Core.Management;

/// <summary>What the management rules need to know about an existing user.</summary>
public sealed record ManagedUser(
    string Id,
    string TenantId,
    PrincipalKind Kind,
    string? RoleKey,
    string? AgencyId,
    string? CorporateId,
    bool IsFoundingAdmin);

/// <summary>The caller of a management operation, with the facts that cannot be read from a token.</summary>
public sealed record ManagementActor(Principal Principal, RoleDefinition Role, bool IsFoundingAdmin);

public enum ManagementOperation
{
    Create,
    ChangeRole,
    Delete,
    EditPermissions,

    /// <summary>Acting as the target user. It needs the same standing as managing them, with no exception for peers.</summary>
    ActOnBehalf,
}

/// <param name="Operation">What the caller wants to do.</param>
/// <param name="Target">The existing user, for every operation except <see cref="ManagementOperation.Create"/>.</param>
/// <param name="NewRole">The role being assigned (create and role change).</param>
/// <param name="AgencyId">The agency the new or changed user will belong to.</param>
/// <param name="CorporateId">The corporate account the new or changed user will belong to.</param>
public sealed record ManagementRequest(
    ManagementOperation Operation,
    ManagedUser? Target = null,
    RoleDefinition? NewRole = null,
    string? AgencyId = null,
    string? CorporateId = null);

public sealed record ManagementDecision(bool Allowed, string? Reason)
{
    public static ManagementDecision Allow { get; } = new(true, null);

    public static ManagementDecision Deny(string reason) => new(false, reason);
}
