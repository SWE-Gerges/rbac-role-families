using System.Linq.Expressions;
using Rbac.Abstractions;

namespace Rbac.Core.Scopes;

/// <summary>The fail-closed fallback: nothing is visible.</summary>
public sealed class NoAccessScope<TResource> : IAccessScopeStrategy<TResource>
{
    public string Name => nameof(NoAccessScope<TResource>);

    public Expression<Func<TResource, bool>> Scope(Principal principal, PermissionSet permissions) => _ => false;
}
