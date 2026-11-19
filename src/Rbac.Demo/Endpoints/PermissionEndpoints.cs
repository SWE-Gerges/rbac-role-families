using Microsoft.AspNetCore.Mvc;
using Rbac.AspNetCore.Authorization;
using Rbac.Core.Catalog;
using Rbac.Core.Management;
using Rbac.Demo.AccessMatrix;
using Rbac.Demo.Contracts;
using Rbac.Persistence.Administration;

namespace Rbac.Demo.Endpoints;

internal static class PermissionEndpoints
{
    public static IEndpointRouteBuilder MapPermissionEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/v1/permissions", ListPermissionsAsync)
            .WithTags("Permissions")
            .WithName("ListPermissions")
            .WithSummary("The permission catalog.")
            .Produces<IReadOnlyList<PermissionResponse>>()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden);

        var roles = app.MapGroup("/api/v1/roles").WithTags("Permissions");

        roles.MapGet("/", ListRolesAsync)
            .WithName("ListRoles")
            .WithSummary("Every role with its family and the stored default permissions of the caller's tenant.")
            .Produces<IReadOnlyList<RoleResponse>>()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden);

        roles.MapGet("/{key}", GetRoleAsync)
            .WithName("GetRole")
            .WithSummary("One role with the stored default permissions of the caller's tenant.")
            .Produces<RoleResponse>()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        roles.MapPut("/{key}/permissions", SetRolePermissionsAsync)
            .WithName("SetRolePermissions")
            .WithSummary("Replaces a role's default permissions in the caller's tenant (system administrators only).")
            .WithDescription(
                "The caller must hold every permission they add or remove, and reserved permissions cannot be touched. Role defaults belong to a tenant, " +
                "so the change applies to the caller's tenant only and revokes the sessions of that tenant's holders of the role.")
            .Produces<RoleResponse>()
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        var userPermissions = app.MapGroup("/api/v1/users/{id}/permissions").WithTags("Permissions")
            .WithMetadata(new ScopedResourceMetadata(ScopedResourceMetadata.User));

        userPermissions.MapGet("/", GetUserPermissionsAsync)
            .WithName("GetUserPermissions")
            .WithSummary("A user's role defaults, per-user grants and revokes, the effective set and the version to send as If-Match.")
            .Produces<UserPermissionsResponse>()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        userPermissions.MapPut("/", EditUserPermissionsAsync)
            .WithName("EditUserPermissions")
            .WithSummary("Grants, revokes or resets per-user permissions. Requires If-Match with the version read before.")
            .WithDescription(
                "The caller can only touch permissions they hold effectively and only users inside their management scope. " +
                "A change revokes the user's sessions and is audited.")
            .Produces<UserPermissionsResponse>()
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status412PreconditionFailed)
            .ProducesProblem(StatusCodes.Status428PreconditionRequired);

        return app;
    }

    [RequirePermission(Permissions.PermissionsView)]
    private static async Task<IResult> ListPermissionsAsync(PermissionAdministration administration, CancellationToken cancellationToken) =>
        Results.Ok((await administration.ListPermissionsAsync(cancellationToken))
            .Select(p => new PermissionResponse(p.Key, p.Description, p.Reserved))
            .ToList());

    [RequirePermission(Permissions.PermissionsView)]
    private static async Task<IResult> ListRolesAsync(PermissionAdministration administration, CancellationToken cancellationToken) =>
        Results.Ok((await administration.ListRolesAsync(cancellationToken)).Select(ToResponse).ToList());

    [RequirePermission(Permissions.PermissionsView)]
    private static async Task<IResult> GetRoleAsync(string key, PermissionAdministration administration, CancellationToken cancellationToken) =>
        (await administration.GetRoleAsync(key, cancellationToken)).ToHttp(role => Results.Ok(ToResponse(role)));

    [RequirePermission(Permissions.RolesManagePermissions)]
    private static async Task<IResult> SetRolePermissionsAsync(
        string key,
        SetRolePermissionsRequest request,
        PermissionAdministration administration,
        CancellationToken cancellationToken) =>
        (await administration.SetRolePermissionsAsync(key, request.Permissions?.ToList(), cancellationToken))
            .ToHttp(role => Results.Ok(ToResponse(role)));

    [RequirePermission(Permissions.PermissionsView)]
    private static async Task<IResult> GetUserPermissionsAsync(
        string id,
        PermissionAdministration administration,
        HttpContext http,
        CancellationToken cancellationToken) =>
        (await administration.GetUserPermissionsAsync(id, cancellationToken)).ToHttp(view => WithETag(http, view));

    [RequirePermission(Permissions.UsersManage)]
    private static async Task<IResult> EditUserPermissionsAsync(
        string id,
        EditUserPermissionsRequest request,
        [FromHeader(Name = "If-Match")] string? ifMatch,
        PermissionAdministration administration,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var diff = new PermissionDiffRequest(request.Grant ?? [], request.Revoke ?? [], request.Reset ?? []);
        return (await administration.EditUserPermissionsAsync(id, ifMatch, diff, cancellationToken)).ToHttp(view => WithETag(http, view));
    }

    private static IResult WithETag(HttpContext http, UserPermissionsView view)
    {
        http.Response.Headers.ETag = $"\"{view.Version}\"";
        return Results.Ok(new UserPermissionsResponse(
            view.UserId, view.RoleKey, view.Version, view.RoleDefaults, view.Grants, view.Revokes, view.Effective));
    }

    private static RoleResponse ToResponse(RoleView role) =>
        new(role.Key, role.Family, role.IsAdmin, role.Permissions, role.CreatableRoleKeys);
}
