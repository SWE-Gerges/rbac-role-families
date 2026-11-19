using System.Collections.Concurrent;
using Rbac.Abstractions;

namespace Rbac.Persistence.Caching;

/// <summary>Counters for the permission cache, so its behaviour can be observed and tested.</summary>
public sealed class PermissionCacheStatistics
{
    private long _hits;
    private long _misses;
    private long _invalidations;
    private long _epochReads;

    /// <summary>Requests answered from the cache.</summary>
    public long Hits => Interlocked.Read(ref _hits);

    /// <summary>Requests that had to resolve permissions from the database.</summary>
    public long Misses => Interlocked.Read(ref _misses);

    /// <summary>Misses where an entry existed but the tenant's epoch had moved on.</summary>
    public long Invalidations => Interlocked.Read(ref _invalidations);

    /// <summary>Single-value epoch reads. There is one per request that needs permissions, hit or miss.</summary>
    public long EpochReads => Interlocked.Read(ref _epochReads);

    internal void RecordHit() => Interlocked.Increment(ref _hits);

    internal void RecordMiss(bool invalidated)
    {
        Interlocked.Increment(ref _misses);
        if (invalidated)
        {
            Interlocked.Increment(ref _invalidations);
        }
    }

    internal void RecordEpochRead() => Interlocked.Increment(ref _epochReads);
}

internal sealed record CachedPermissions(long Epoch, PermissionSet Permissions);

/// <summary>
/// A bounded in-process map from a principal's identity to its permissions and the epoch they were resolved under. It does
/// no expiry of its own: whether an entry is still good is decided by comparing its epoch with the tenant's current one.
/// </summary>
public sealed class PermissionCache(int capacity = PermissionCache.DefaultCapacity)
{
    public const int DefaultCapacity = 10_000;

    private readonly ConcurrentDictionary<string, CachedPermissions> _entries = new(StringComparer.Ordinal);

    public int Count => _entries.Count;

    internal static string KeyFor(Principal principal) =>
        string.Join('|', principal.TenantId, principal.UserId, principal.Kind, principal.RoleKey);

    internal bool TryGet(string key, out CachedPermissions entry) => _entries.TryGetValue(key, out entry!);

    /// <summary>Stores an entry unless a newer one is already there, so a slow request cannot overwrite a fresher answer.</summary>
    internal void Set(string key, CachedPermissions entry)
    {
        if (_entries.Count >= capacity && !_entries.ContainsKey(key))
        {
            // Simple and bounded: everything is cheap to recompute, so dropping the lot beats tracking recency.
            _entries.Clear();
        }

        _entries.AddOrUpdate(key, entry, (_, existing) => existing.Epoch > entry.Epoch ? existing : entry);
    }
}
