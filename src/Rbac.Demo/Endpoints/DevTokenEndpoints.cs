using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Rbac.Abstractions;
using Rbac.AspNetCore.Claims;
using Rbac.Demo.Contracts;
using Rbac.Persistence;

namespace Rbac.Demo.Endpoints;

internal static class DevTokenEndpoints
{
    /// <summary>
    /// Demo only. Issues a signed token for any seeded user with no credentials, which is exactly what a real
    /// deployment must never do. It is mapped only when <c>Demo:EnableDevTokens</c> is true.
    /// </summary>
    public static IEndpointRouteBuilder MapDevTokenEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/v1/dev/token", IssueAsync)
            .AllowAnonymous()
            .WithTags("Development")
            .WithName("IssueDevToken")
            .WithSummary("DEMO ONLY: issues a token for a seeded user. Enabled only when Demo:EnableDevTokens is true.")
            .Produces<DevTokenResponse>()
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status404NotFound);

        return app;
    }

    private static async Task<IResult> IssueAsync(
        DevTokenRequest request,
        RbacDbContext db,
        ITokenVersionStore versions,
        DevTokenIssuer issuer,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.UserId))
        {
            return Results.ValidationProblem(new Dictionary<string, string[]> { [nameof(request.UserId)] = ["UserId is required."] });
        }

        var user = await db.Users
            .IgnoreQueryFilters()
            .AsNoTracking()
            .Where(u => (u.Id == request.UserId || u.Handle == request.UserId) && u.IsActive && u.DeletedAt == null)
            .OrderByDescending(u => u.Id == request.UserId)
            .FirstOrDefaultAsync(cancellationToken);

        if (user is null)
        {
            return Results.Problem(
                statusCode: StatusCodes.Status404NotFound,
                title: "Unknown demo user.",
                detail: "No active seeded user has that id.");
        }

        var version = await versions.GetCurrentVersionAsync(user.TenantId, user.Id, cancellationToken);
        var principal = user.Kind == PrincipalKind.Customer
            ? Principal.ForCustomer(user.Id, user.TenantId, version)
            : Principal.ForStaff(user.Id, user.TenantId, user.RoleKey ?? string.Empty, user.AgencyId, user.CorporateId, version);

        var token = issuer.Issue(PrincipalClaims.ToClaims(principal));
        return Results.Ok(new DevTokenResponse(
            token.AccessToken,
            "Bearer",
            token.ExpiresAt,
            user.Id,
            user.TenantId,
            principal.Kind,
            principal.RoleKey));
    }
}
