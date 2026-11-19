using System.Text.Json;
using System.Text.Json.Serialization;
using Rbac.Abstractions;
using Rbac.Persistence.Entities;

namespace Rbac.Persistence.Administration;

public sealed record AuditRecord(string Action, string TargetType, string TargetId, object? Before = null, object? After = null);

/// <summary>
/// Adds audit entries to the current unit of work. An entry is only persisted by the same <c>SaveChanges</c> that
/// persists the change it describes, so the two succeed or fail together.
/// </summary>
public interface IAuditLog
{
    void Append(AuditRecord record);
}

internal sealed class AuditLog(
    RbacDbContext db,
    IPrincipalContext principalContext,
    ICorrelationContext correlation,
    TimeProvider clock) : IAuditLog
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    public void Append(AuditRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        var principal = principalContext.Current;
        if (principal.IsAnonymous)
        {
            throw new InvalidOperationException("An audit entry needs an authenticated actor and tenant.");
        }

        db.Add(new AuditEntryEntity
        {
            Id = $"aud-{Guid.CreateVersion7():N}",
            TenantId = principal.TenantId,
            ActorUserId = principal.ActingUserId,
            EffectiveUserId = principal.IsOnBehalf ? principal.EffectiveUserId : null,
            Action = record.Action,
            TargetType = record.TargetType,
            TargetId = record.TargetId,
            Before = record.Before is null ? null : JsonSerializer.Serialize(record.Before, Json),
            After = record.After is null ? null : JsonSerializer.Serialize(record.After, Json),
            CorrelationId = correlation.CorrelationId,
            At = clock.GetUtcNow(),
        });
    }
}
