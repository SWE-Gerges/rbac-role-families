using Microsoft.EntityFrameworkCore;

namespace Rbac.Persistence;

/// <summary>Creates the SQLite schema. Anything the Postgres migrations do beyond tables (triggers) belongs here too.</summary>
public static class SqliteSchema
{
    /// <summary>The audit trail is append-only in the database as well: statements that bypass EF's change tracker are rejected here.</summary>
    internal const string AuditAppendOnlyTriggers =
        """
        CREATE TRIGGER IF NOT EXISTS "AuditEntry_no_update" BEFORE UPDATE ON "AuditEntry"
        BEGIN SELECT RAISE(ABORT, 'audit entries are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS "AuditEntry_no_delete" BEFORE DELETE ON "AuditEntry"
        BEGIN SELECT RAISE(ABORT, 'audit entries are append-only'); END;
        """;

    public static async Task CreateAsync(RbacDbContext db, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);
        await db.Database.EnsureCreatedAsync(cancellationToken);
        await db.Database.ExecuteSqlRawAsync(AuditAppendOnlyTriggers, cancellationToken);
    }
}
