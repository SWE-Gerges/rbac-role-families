using Rbac.Abstractions;
using Rbac.Demo.Contracts;

namespace Rbac.Demo.Endpoints;

internal static class MeEndpoints
{
    public static IEndpointRouteBuilder MapMeEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/v1/me", GetAsync)
            .WithTags("Identity")
            .WithName("GetMe")
            .WithSummary("Shows how the caller is seen: principal kind, role, family and live effective permissions.")
            .Produces<MeResponse>()
            .ProducesProblem(StatusCodes.Status401Unauthorized);

        return app;
    }

    private static async Task<IResult> GetAsync(
        IPrincipalContext principalContext,
        ICurrentPermissions permissions,
        IRoleCatalog catalog,
        CancellationToken cancellationToken)
    {
        var principal = principalContext.Current;
        var granted = await permissions.GetAsync(cancellationToken);
        var family = principal.Kind == PrincipalKind.Staff ? catalog.Find(principal.RoleKey)?.Family : null;

        return Results.Ok(new MeResponse(
            principal.Kind,
            principal.IsAnonymous ? null : principal.UserId,
            principal.IsAnonymous ? null : principal.TenantId,
            principal.RoleKey,
            family,
            principal.AgencyId,
            principal.CorporateId,
            principal.TokenVersion,
            [.. granted.Order(StringComparer.Ordinal)],
            principal.IsOnBehalf ? principal.ActingUserId : null));
    }
}
