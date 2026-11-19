using Rbac.Abstractions;
using Rbac.Core.Catalog;

namespace Rbac.Core.Management;

public sealed record CeilingViolation(string Permission, string Reason);

/// <summary>
/// The grant ceiling: a caller may touch (grant, revoke or reset) only permissions they currently hold effectively, and
/// never a reserved permission. A permission list sent by a client is checked against this and never trusted.
/// Revoking is held to the same bar as granting: you can take away only what you could hand out.
/// </summary>
public static class GrantCeiling
{
    public static IReadOnlyList<CeilingViolation> Check(PermissionSet held, IEnumerable<string> touched)
    {
        ArgumentNullException.ThrowIfNull(held);
        ArgumentNullException.ThrowIfNull(touched);

        var violations = new List<CeilingViolation>();
        foreach (var permission in touched.Distinct(StringComparer.Ordinal))
        {
            if (Permissions.Reserved.Contains(permission))
            {
                violations.Add(new CeilingViolation(permission, "A reserved permission cannot be granted or revoked through the API."));
            }
            else if (!held.Has(permission))
            {
                violations.Add(new CeilingViolation(permission, "You do not hold this permission, so you cannot grant or revoke it."));
            }
        }

        return violations;
    }
}

/// <summary>A client's edit of one user's per-user overrides. A permission may appear in at most one list.</summary>
/// <param name="Grant">Make the permission effective for the user.</param>
/// <param name="Revoke">Make the permission not effective for the user.</param>
/// <param name="Reset">Remove any override so the role default applies again.</param>
public sealed record PermissionDiffRequest(
    IReadOnlyCollection<string> Grant,
    IReadOnlyCollection<string> Revoke,
    IReadOnlyCollection<string> Reset)
{
    public IEnumerable<string> Touched => Grant.Concat(Revoke).Concat(Reset);

    public static PermissionDiffRequest Empty { get; } = new([], [], []);
}

public sealed record PermissionDiffResult(IReadOnlyDictionary<string, bool> Overrides, IReadOnlyList<string> Changed)
{
    public bool HasChanges => Changed.Count > 0;
}

/// <summary>
/// Applies a diff to a user's overrides (<c>true</c> = grant, <c>false</c> = revoke) and keeps them minimal: an override
/// is stored only when it differs from what the role default already gives. Granting something the role already gives, or
/// revoking something it does not, stores nothing, so the same diff applied twice changes nothing the second time.
/// </summary>
public static class PermissionDiffer
{
    public static IReadOnlyList<string> Duplicates(PermissionDiffRequest request) =>
        [.. request.Touched.GroupBy(p => p, StringComparer.Ordinal).Where(g => g.Count() > 1).Select(g => g.Key).Order(StringComparer.Ordinal)];

    public static PermissionDiffResult Apply(
        IReadOnlySet<string> roleDefaults,
        IReadOnlyDictionary<string, bool> current,
        PermissionDiffRequest request)
    {
        ArgumentNullException.ThrowIfNull(roleDefaults);
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(request);

        var next = new Dictionary<string, bool>(current, StringComparer.Ordinal);
        var changed = new List<string>();

        void Set(string permission, bool? desiredGrant)
        {
            next.Remove(permission);
            if (desiredGrant is { } grant && grant != roleDefaults.Contains(permission))
            {
                next[permission] = grant;
            }

            if (current.TryGetValue(permission, out var before) != next.TryGetValue(permission, out var after) || before != after)
            {
                changed.Add(permission);
            }
        }

        foreach (var permission in request.Grant)
        {
            Set(permission, true);
        }

        foreach (var permission in request.Revoke)
        {
            Set(permission, false);
        }

        foreach (var permission in request.Reset)
        {
            Set(permission, null);
        }

        return new PermissionDiffResult(next, [.. changed.Order(StringComparer.Ordinal)]);
    }

    /// <summary>Role defaults plus grants minus revokes.</summary>
    public static IReadOnlyList<string> Effective(IEnumerable<string> roleDefaults, IReadOnlyDictionary<string, bool> overrides)
    {
        var effective = new HashSet<string>(roleDefaults, StringComparer.Ordinal);
        foreach (var (permission, grant) in overrides)
        {
            if (grant)
            {
                effective.Add(permission);
            }
            else
            {
                effective.Remove(permission);
            }
        }

        return [.. effective.Order(StringComparer.Ordinal)];
    }
}
