using System.Linq.Expressions;
using Rbac.Abstractions;

namespace Rbac.Core.Scopes;

/// <summary>
/// Decorates a strategy with an extra predicate. The result is the conjunction of both,
/// so narrowing can only ever reduce what the inner strategy allows.
/// </summary>
public sealed class NarrowedScope<TResource>(IAccessScopeStrategy<TResource> inner, Expression<Func<TResource, bool>> extra)
    : IAccessScopeStrategy<TResource>
{
    public string Name => inner.Name;

    public Expression<Func<TResource, bool>> Scope(Principal principal, PermissionSet permissions) =>
        PredicateCombiner.And(inner.Scope(principal, permissions), extra);
}

public static class AccessScope
{
    public static IAccessScopeStrategy<TResource> Narrow<TResource>(
        this IAccessScopeStrategy<TResource> inner,
        Expression<Func<TResource, bool>> extra)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(extra);
        return new NarrowedScope<TResource>(inner, extra);
    }
}
