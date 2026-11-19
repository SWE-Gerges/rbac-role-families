using Rbac.Abstractions;
using Rbac.AspNetCore.Authorization;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;
using Rbac.Core.Management;
using Rbac.Core.Registry;
using Rbac.Core.Users;
using Rbac.Demo.AccessMatrix;
using Rbac.Demo.Contracts;
using Rbac.Persistence;

namespace Rbac.Demo.Endpoints;

internal static class AccessMatrixEndpoints
{
    public static IEndpointRouteBuilder MapAccessMatrixEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/v1/access-matrix", GetAsync)
            .WithTags("Administration")
            .WithName("GetAccessMatrix")
            .WithSummary("Role by action matrix computed from the caller's tenant's stored role defaults, the strategy registries and the endpoint permissions.")
            .WithDescription(
                "The same model as docs/access-matrix.md, which is generated from the code-defined catalog. This response uses the caller's tenant's stored role defaults, " +
                "so it follows edits made through the administration API. Per-user grants and revokes are not reflected.")
            .Produces<AccessMatrixResponse>()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden);

        return app;
    }

    [RequirePermission(Permissions.AccessMatrixView)]
    private static async Task<IResult> GetAsync(
        RbacDbContext db,
        IPrincipalContext principalContext,
        StrategyRegistry<Booking> bookingScopes,
        StrategyRegistry<User> userScopes,
        RoleManagementRegistry management,
        EndpointDataSource endpoints,
        CancellationToken cancellationToken)
    {
        var stored = await RoleCatalogStore.LoadAsync(db, principalContext.Current.TenantId, cancellationToken);
        return Results.Ok(AccessMatrixBuilder.Build(stored.Roles, bookingScopes, userScopes, management, endpoints.Endpoints));
    }
}
