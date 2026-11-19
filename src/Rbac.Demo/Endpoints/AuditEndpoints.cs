using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Rbac.AspNetCore.Authorization;
using Rbac.Core.Catalog;
using Rbac.Demo.Contracts;
using Rbac.Persistence;
using Rbac.Persistence.Entities;

namespace Rbac.Demo.Endpoints;

internal static class AuditEndpoints
{
    private const int DefaultPageSize = 20;
    private const int MaxPageSize = 100;

    public static IEndpointRouteBuilder MapAuditEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/v1/audit", ListAsync)
            .WithTags("Audit")
            .WithName("ListAuditEntries")
            .WithSummary("The audit trail of the caller's tenant, newest first.")
            .WithDescription(
                "Entries are written in the same transaction as the change and can never be edited or removed. " +
                "Filter by target id (target) or by the acting user (actor).")
            .Produces<AuditListResponse>()
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden);

        return app;
    }

    [RequirePermission(Permissions.AuditView)]
    private static async Task<IResult> ListAsync(
        RbacDbContext db,
        [FromQuery] string? target,
        [FromQuery] string? actor,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken cancellationToken)
    {
        var errors = new Dictionary<string, string[]>();
        var pageNumber = page ?? 1;
        if (pageNumber < 1)
        {
            errors[nameof(page)] = ["page must be 1 or greater."];
        }

        var size = pageSize ?? DefaultPageSize;
        if (size is < 1 or > MaxPageSize)
        {
            errors[nameof(pageSize)] = [$"pageSize must be between 1 and {MaxPageSize}."];
        }

        if (errors.Count > 0)
        {
            return Results.ValidationProblem(errors);
        }

        // The tenant filter on the audit table is what scopes this query to the caller's tenant.
        var query = db.AuditEntries;
        if (!string.IsNullOrWhiteSpace(target))
        {
            query = query.Where(e => e.TargetId == target);
        }

        if (!string.IsNullOrWhiteSpace(actor))
        {
            query = query.Where(e => e.ActorUserId == actor);
        }

        var total = await query.CountAsync(cancellationToken);
        var items = await query
            .OrderByDescending(e => e.At)
            .ThenByDescending(e => e.Id)
            .Skip((pageNumber - 1) * size)
            .Take(size)
            .ToListAsync(cancellationToken);

        return Results.Ok(new AuditListResponse([.. items.Select(ToResponse)], pageNumber, size, total));
    }

    private static AuditEntryResponse ToResponse(AuditEntryEntity entry) => new(
        entry.Id,
        entry.TenantId,
        entry.ActorUserId,
        entry.EffectiveUserId,
        entry.Action,
        entry.TargetType,
        entry.TargetId,
        Parse(entry.Before),
        Parse(entry.After),
        entry.CorrelationId,
        entry.At);

    private static JsonElement? Parse(string? json)
    {
        if (json is null)
        {
            return null;
        }

        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }
}
