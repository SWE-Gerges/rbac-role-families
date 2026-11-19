using System.Linq.Expressions;

namespace Rbac.Abstractions;

/// <summary>
/// Decides what rows a caller may see by producing the query predicate itself.
/// Implementations must be pure: no I/O and nothing that cannot be translated to SQL.
/// </summary>
public interface IAccessScopeStrategy<TResource>
{
    string Name { get; }

    Expression<Func<TResource, bool>> Scope(Principal principal, PermissionSet permissions);
}
