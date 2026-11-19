using System.Linq.Expressions;

namespace Rbac.Abstractions;

/// <summary>Picks the strategy for a caller from an explicit registry. Never returns null: unknown callers get no access.</summary>
public interface IScopeResolver<TResource>
{
    IAccessScopeStrategy<TResource> StrategyFor(Principal principal);

    Expression<Func<TResource, bool>> Resolve(Principal principal, PermissionSet permissions) =>
        StrategyFor(principal).Scope(principal, permissions);
}
