using Rbac.Abstractions;

namespace Rbac.Persistence.Caching;

/// <summary>
/// Caches resolved permissions in process and validates them against the tenant's persisted epoch on every call.
/// The epoch is read <em>before</em> the permissions are resolved and stamped on the entry, so a write that lands in between
/// leaves the entry with the older epoch and it is refreshed on the next request: a cached answer is never newer than its stamp.
/// Cost per request: one primary-key read for the epoch. A miss adds the three queries of the underlying store.
/// </summary>
public sealed class CachingPermissionStore(
    IPermissionStore inner,
    RbacDbContext db,
    PermissionCache cache,
    PermissionCacheStatistics statistics) : IPermissionStore
{
    public async ValueTask<PermissionSet> GetEffectivePermissionsAsync(Principal principal, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (principal.IsAnonymous)
        {
            return PermissionSet.Empty;
        }

        var epoch = await PermissionEpoch.ReadAsync(db, principal.TenantId, cancellationToken);
        statistics.RecordEpochRead();

        var key = PermissionCache.KeyFor(principal);
        var found = cache.TryGet(key, out var cached);
        if (found && cached.Epoch == epoch)
        {
            statistics.RecordHit();
            return cached.Permissions;
        }

        statistics.RecordMiss(invalidated: found);
        var resolved = await inner.GetEffectivePermissionsAsync(principal, cancellationToken);
        cache.Set(key, new CachedPermissions(epoch, resolved));
        return resolved;
    }
}
