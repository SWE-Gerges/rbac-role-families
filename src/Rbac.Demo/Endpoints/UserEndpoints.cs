using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Rbac.Abstractions;
using Rbac.AspNetCore.Authorization;
using Rbac.Core.Catalog;
using Rbac.Core.Users;
using Rbac.Demo.AccessMatrix;
using Rbac.Demo.Contracts;
using Rbac.Persistence.Administration;

namespace Rbac.Demo.Endpoints;

internal static class UserEndpoints
{
    private const int DefaultPageSize = 20;
    private const int MaxPageSize = 100;

    public static IEndpointRouteBuilder MapUserEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/users").WithTags("Users").WithMetadata(new ScopedResourceMetadata(ScopedResourceMetadata.User));

        group.MapPost("/", CreateAsync)
            .WithName("CreateUser")
            .WithSummary("Creates a user. The caller's role must list the new role as creatable, and account-bound roles are created inside the caller's own account.")
            .Produces<UserResponse>(StatusCodes.Status201Created)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status409Conflict);

        group.MapGet("/", ListAsync)
            .WithName("ListUsers")
            .WithSummary("Lists the users the caller may see. The same scope rule applies to by-id lookups.")
            .Produces<UserListResponse>()
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden);

        group.MapGet("/{id}", GetAsync)
            .WithName("GetUser")
            .WithSummary("Gets one user. A user outside the caller's scope is indistinguishable from a missing one (404).")
            .Produces<UserResponse>()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPut("/{id}/role", ChangeRoleAsync)
            .WithName("ChangeUserRole")
            .WithSummary("Changes a user's role. Revokes the user's sessions.")
            .Produces<UserResponse>()
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict);

        group.MapDelete("/{id}", DeleteAsync)
            .WithName("DeleteUser")
            .WithSummary("Soft deletes a user. The user disappears from every query and their tokens stop working.")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict);

        return app;
    }

    [RequirePermission(Permissions.UsersCreate)]
    private static async Task<IResult> CreateAsync(
        CreateUserRequest request,
        UserAdministration administration,
        IRoleCatalog catalog,
        CancellationToken cancellationToken)
    {
        var result = await administration.CreateAsync(
            new CreateUserCommand(request.Handle, request.DisplayName, request.RoleKey, request.AgencyId, request.CorporateId),
            cancellationToken);

        return result.ToHttp(
            user => Results.Ok(ToResponse(user, catalog)),
            user => Results.Created($"/api/v1/users/{user.Id}", ToResponse(user, catalog)));
    }

    [RequirePermission(Permissions.UsersRead)]
    private static async Task<IResult> ListAsync(
        IPrincipalContext principalContext,
        ICurrentPermissions permissions,
        IScopedQuery<User> users,
        IRoleCatalog catalog,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        [FromQuery] string? role,
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

        var granted = await permissions.GetAsync(cancellationToken);
        var query = users.ScopedFor(principalContext.Current, granted);
        if (!string.IsNullOrWhiteSpace(role))
        {
            query = query.Where(u => u.RoleKey == role);
        }

        var total = await query.CountAsync(cancellationToken);
        var items = await query
            .AsNoTracking()
            .OrderBy(u => u.Handle)
            .ThenBy(u => u.Id)
            .Skip((pageNumber - 1) * size)
            .Take(size)
            .ToListAsync(cancellationToken);

        return Results.Ok(new UserListResponse([.. items.Select(u => ToResponse(u, catalog))], pageNumber, size, total));
    }

    [RequirePermission(Permissions.UsersRead)]
    private static async Task<IResult> GetAsync(
        string id,
        IPrincipalContext principalContext,
        ICurrentPermissions permissions,
        IScopedQuery<User> users,
        IRoleCatalog catalog,
        CancellationToken cancellationToken)
    {
        var granted = await permissions.GetAsync(cancellationToken);
        var user = await users
            .ScopedFor(principalContext.Current, granted)
            .AsNoTracking()
            .Where(u => u.Id == id)
            .FirstOrDefaultAsync(cancellationToken);

        return user is null ? AdminResultMapping.NotFound() : Results.Ok(ToResponse(user, catalog));
    }

    [RequirePermission(Permissions.UsersManage)]
    private static async Task<IResult> ChangeRoleAsync(
        string id,
        ChangeRoleRequest request,
        UserAdministration administration,
        IRoleCatalog catalog,
        CancellationToken cancellationToken)
    {
        var result = await administration.ChangeRoleAsync(
            id,
            new ChangeRoleCommand(request.RoleKey, request.AgencyId, request.CorporateId),
            cancellationToken);

        return result.ToHttp(user => Results.Ok(ToResponse(user, catalog)));
    }

    [RequirePermission(Permissions.UsersManage)]
    private static async Task<IResult> DeleteAsync(
        string id,
        UserAdministration administration,
        CancellationToken cancellationToken) =>
        (await administration.DeleteAsync(id, cancellationToken)).ToHttp(_ => Results.NoContent());

    internal static UserResponse ToResponse(User user, IRoleCatalog catalog) => new(
        user.Id,
        user.TenantId,
        user.Handle,
        user.DisplayName,
        user.Kind,
        user.RoleKey,
        user.Kind == PrincipalKind.Staff ? catalog.Find(user.RoleKey)?.Family : null,
        user.AgencyId,
        user.CorporateId,
        user.IsFoundingAdmin,
        user.PermissionsVersion);
}
