using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Rbac.Persistence.Entities;

namespace Rbac.Persistence.Administration;

/// <summary>Thrown when code tries to change or remove an audit entry. The audit trail only ever grows.</summary>
public sealed class AuditTrailImmutableException(string message) : InvalidOperationException(message);

/// <summary>
/// Refuses to save a unit of work that modifies or deletes an audit entry. It throws before anything is written, so the other
/// changes in the same <c>SaveChanges</c> are not persisted either. This guards the EF path; set-based statements
/// (<c>ExecuteUpdate</c>, <c>ExecuteDelete</c>, raw SQL) bypass the change tracker and are stopped by the database triggers.
/// </summary>
public sealed class AuditAppendOnlyInterceptor : SaveChangesInterceptor
{
    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        Check(eventData.Context);
        return base.SavingChanges(eventData, result);
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        Check(eventData.Context);
        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    private static void Check(DbContext? context)
    {
        if (context is null)
        {
            return;
        }

        var offender = context.ChangeTracker.Entries<AuditEntryEntity>()
            .FirstOrDefault(e => e.State is EntityState.Modified or EntityState.Deleted);
        if (offender is not null)
        {
            throw new AuditTrailImmutableException(
                $"Audit entry '{offender.Entity.Id}' cannot be {(offender.State == EntityState.Deleted ? "deleted" : "modified")}: the audit trail is append-only.");
        }
    }
}
