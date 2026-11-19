using System.Linq.Expressions;

namespace Rbac.Abstractions;

/// <summary>
/// The only way to read scoped resources. Lists, dashboards and by-id lookups all start here,
/// so they cannot drift apart.
/// </summary>
public interface IScopedQuery<TResource>
{
    /// <param name="principal">The caller.</param>
    /// <param name="permissions">The caller's live permissions.</param>
    /// <param name="narrowing">Optional extra predicate. It can only reduce what the caller sees.</param>
    IQueryable<TResource> ScopedFor(
        Principal principal,
        PermissionSet permissions,
        Expression<Func<TResource, bool>>? narrowing = null);
}
