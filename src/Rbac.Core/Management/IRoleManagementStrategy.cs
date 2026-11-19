using Rbac.Abstractions;

namespace Rbac.Core.Management;

/// <summary>
/// Decides whether a caller may create, re-role, delete or edit the permissions of a user. It is chosen per role family
/// from an explicit registry, exactly like the data scope strategies. Whether the target is visible to the caller at all
/// is a separate question answered by the user scope; this one is only about what the caller may do to a visible user.
/// </summary>
public interface IRoleManagementStrategy
{
    string Name { get; }

    ManagementDecision Evaluate(ManagementActor actor, ManagementRequest request, IRoleCatalog catalog);
}
