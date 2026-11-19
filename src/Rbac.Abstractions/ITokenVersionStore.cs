namespace Rbac.Abstractions;

/// <summary>
/// Holds the current token version per user. Bumping it invalidates every token issued earlier,
/// which is how role and permission edits revoke live sessions.
/// </summary>
public interface ITokenVersionStore
{
    /// <summary>The version a freshly issued token must carry. Users that were never bumped are on version 1.</summary>
    ValueTask<int> GetCurrentVersionAsync(string tenantId, string userId, CancellationToken cancellationToken);

    ValueTask<int> BumpAsync(string tenantId, string userId, CancellationToken cancellationToken);
}
