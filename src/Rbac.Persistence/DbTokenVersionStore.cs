using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Rbac.Abstractions;

namespace Rbac.Persistence;

/// <summary>
/// Token versions in the database, so a restart or a second instance never forgets a bump. A bump is one atomic
/// upsert-increment statement. It is a singleton (it is called from the JWT bearer events) and opens its own scope per call.
/// </summary>
internal sealed class DbTokenVersionStore(IServiceScopeFactory scopeFactory) : ITokenVersionStore
{
    public async ValueTask<int> GetCurrentVersionAsync(string tenantId, string userId, CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<RbacDbContext>();
        return await ReadAsync(db, tenantId, userId, cancellationToken);
    }

    public async ValueTask<int> BumpAsync(string tenantId, string userId, CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<RbacDbContext>();
        await BumpAsync(db, tenantId, userId, cancellationToken);
        return await ReadAsync(db, tenantId, userId, cancellationToken);
    }

    /// <summary>Increments a user's version on the given context, inside whatever transaction it has open.</summary>
    public static async Task BumpAsync(RbacDbContext db, string tenantId, string userId, CancellationToken cancellationToken) =>
        await db.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO "TokenVersion" ("TenantId", "UserId", "Version") VALUES ({tenantId}, {userId}, 2)
            ON CONFLICT ("TenantId", "UserId") DO UPDATE SET "Version" = "TokenVersion"."Version" + 1
            """,
            cancellationToken);

    private static async Task<int> ReadAsync(RbacDbContext db, string tenantId, string userId, CancellationToken cancellationToken) =>
        await db.TokenVersions
            .AsNoTracking()
            .Where(t => t.TenantId == tenantId && t.UserId == userId)
            .Select(t => (int?)t.Version)
            .SingleOrDefaultAsync(cancellationToken) ?? 1;
}
