using Rbac.Abstractions;

namespace Rbac.Core.Management;

/// <summary>
/// Privilege is defined by the creation graph: a role outranks the roles it can reach by following
/// <see cref="RoleDefinition.CreatableRoleKeys"/>, directly or through other roles, but never itself.
/// </summary>
public static class RolePrivilege
{
    /// <summary>Every role reachable from the role, excluding the role itself.</summary>
    public static IReadOnlySet<string> Reachable(IRoleCatalog catalog, string roleKey)
    {
        var reached = new HashSet<string>(StringComparer.Ordinal);
        var pending = new Queue<string>();
        pending.Enqueue(roleKey);

        while (pending.Count > 0)
        {
            var current = catalog.Find(pending.Dequeue());
            if (current is null)
            {
                continue;
            }

            foreach (var next in current.CreatableRoleKeys)
            {
                if (next != roleKey && reached.Add(next))
                {
                    pending.Enqueue(next);
                }
            }
        }

        return reached;
    }

    /// <summary>
    /// Whether the actor is strictly more privileged than the target. Customers sit below every staff role that
    /// belongs to the system or internal families.
    /// </summary>
    public static bool Outranks(IRoleCatalog catalog, RoleDefinition actorRole, PrincipalKind targetKind, string? targetRoleKey)
    {
        if (targetKind == PrincipalKind.Customer)
        {
            return actorRole.Family is RoleFamily.System or RoleFamily.Internal;
        }

        return targetRoleKey is not null && Reachable(catalog, actorRole.Key).Contains(targetRoleKey);
    }
}
