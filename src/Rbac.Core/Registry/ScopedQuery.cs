using System.Linq.Expressions;
using Rbac.Abstractions;
using Rbac.Core.Scopes;

namespace Rbac.Core.Registry;

/// <summary>Applies the caller's scope predicate to a source query.</summary>
public sealed class ScopedQuery<TResource>(IQueryable<TResource> source, IScopeResolver<TResource> resolver)
    : IScopedQuery<TResource>
{
    public IQueryable<TResource> ScopedFor(
        Principal principal,
        PermissionSet permissions,
        Expression<Func<TResource, bool>>? narrowing = null) =>
        source.ScopedFor(resolver, principal, permissions, narrowing);
}

public static class ScopedQueryExtensions
{
    public static IQueryable<TResource> ScopedFor<TResource>(
        this IQueryable<TResource> query,
        IScopeResolver<TResource> resolver,
        Principal principal,
        PermissionSet permissions,
        Expression<Func<TResource, bool>>? narrowing = null)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(permissions);

        var strategy = resolver.StrategyFor(principal);
        if (narrowing is not null)
        {
            strategy = strategy.Narrow(narrowing);
        }

        return query.Where(strategy.Scope(principal, permissions));
    }
}
