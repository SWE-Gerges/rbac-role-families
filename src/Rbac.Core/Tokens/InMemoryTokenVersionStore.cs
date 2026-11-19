using System.Collections.Concurrent;
using Rbac.Abstractions;

namespace Rbac.Core.Tokens;

/// <summary>
/// Single-instance token version store. A multi-instance deployment needs a shared store
/// with cache invalidation, which is on the roadmap.
/// </summary>
public sealed class InMemoryTokenVersionStore : ITokenVersionStore
{
    private const int InitialVersion = 1;

    private readonly ConcurrentDictionary<(string TenantId, string UserId), int> _versions = new();

    public ValueTask<int> GetCurrentVersionAsync(string tenantId, string userId, CancellationToken cancellationToken) =>
        ValueTask.FromResult(_versions.GetValueOrDefault((tenantId, userId), InitialVersion));

    public ValueTask<int> BumpAsync(string tenantId, string userId, CancellationToken cancellationToken) =>
        ValueTask.FromResult(_versions.AddOrUpdate((tenantId, userId), InitialVersion + 1, (_, current) => current + 1));
}
