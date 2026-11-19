using Rbac.Abstractions;
using Rbac.AspNetCore.Authorization;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;
using Rbac.Core.Management;
using Rbac.Core.Registry;
using Rbac.Core.Users;
using Rbac.Demo.Contracts;

namespace Rbac.Demo.AccessMatrix;

/// <summary>
/// Names the resource whose scope strategy decides which rows an endpoint can reach. It lets the access matrix say, for each
/// permission-gated endpoint, which scope applies, without anyone writing that down twice.
/// </summary>
internal sealed record ScopedResourceMetadata(string Resource)
{
    public const string Booking = "Booking";
    public const string User = "User";
}

/// <summary>
/// Computes the role by action matrix from the things that decide access at runtime: the role definitions with their default
/// permissions, the scope strategy registries, the management registry and the permission each endpoint declares. Nothing is
/// written down by hand, so the matrix cannot disagree with the code.
/// </summary>
internal static class AccessMatrixBuilder
{
    private static readonly string[] MethodOrder = ["GET", "POST", "PUT", "PATCH", "DELETE"];

    private sealed record ActionSource(AccessMatrixAction Action, IReadOnlyList<string> Required);

    public static AccessMatrixResponse Build(
        IReadOnlyList<RoleDefinition> roles,
        StrategyRegistry<Booking> bookingScopes,
        StrategyRegistry<User> userScopes,
        RoleManagementRegistry management,
        IEnumerable<Endpoint> endpoints)
    {
        ArgumentNullException.ThrowIfNull(roles);
        ArgumentNullException.ThrowIfNull(bookingScopes);
        ArgumentNullException.ThrowIfNull(userScopes);
        ArgumentNullException.ThrowIfNull(management);
        ArgumentNullException.ThrowIfNull(endpoints);

        var actions = ActionsFrom(endpoints);
        var rows = new List<AccessMatrixRow>();

        foreach (var role in roles)
        {
            rows.Add(Row(
                role.Key,
                PrincipalKind.Staff,
                role.Family,
                role.IsAdmin,
                bookingScopes.ForFamily(role.Family).Name,
                userScopes.ForFamily(role.Family).Name,
                management.ForFamily(role.Family).Name,
                role.CreatableRoleKeys,
                role.DefaultPermissions,
                actions));
        }

        rows.Add(Row(
            "customer",
            PrincipalKind.Customer,
            null,
            false,
            (bookingScopes.Customer ?? bookingScopes.Fallback).Name,
            (userScopes.Customer ?? userScopes.Fallback).Name,
            management.Fallback.Name,
            [],
            Permissions.CustomerDefaults.ToHashSet(StringComparer.Ordinal),
            actions));
        rows.Add(Row(
            "anonymous",
            PrincipalKind.Anonymous,
            null,
            false,
            bookingScopes.Fallback.Name,
            userScopes.Fallback.Name,
            management.Fallback.Name,
            [],
            new HashSet<string>(StringComparer.Ordinal),
            actions));

        return new AccessMatrixResponse(
            [.. actions.Select(a => a.Action)],
            [.. Permissions.Definitions.Select(d => new AccessMatrixPermission(d.Key, d.Description, Permissions.Reserved.Contains(d.Key)))],
            rows);
    }

    private static AccessMatrixRow Row(
        string subject,
        PrincipalKind kind,
        RoleFamily? family,
        bool isAdmin,
        string bookingScope,
        string userScope,
        string managementStrategy,
        IReadOnlyList<string> canCreate,
        IReadOnlySet<string> defaults,
        IReadOnlyList<ActionSource> actions) => new(
        subject,
        kind,
        family,
        isAdmin,
        new Dictionary<string, string>
        {
            [ScopedResourceMetadata.Booking] = bookingScope,
            [ScopedResourceMetadata.User] = userScope,
        },
        managementStrategy,
        canCreate,
        [.. defaults.Order(StringComparer.Ordinal)],
        actions.ToDictionary(a => a.Action.Id, a => a.Required.All(defaults.Contains), StringComparer.Ordinal));

    private static List<ActionSource> ActionsFrom(IEnumerable<Endpoint> endpoints)
    {
        var sources = new List<ActionSource>();

        foreach (var endpoint in endpoints.OfType<RouteEndpoint>())
        {
            var required = endpoint.Metadata.OfType<RequirePermissionAttribute>().Select(a => a.Permission).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            if (required.Length == 0)
            {
                continue;
            }

            var path = endpoint.RoutePattern.RawText!.TrimEnd('/');
            var resource = endpoint.Metadata.GetMetadata<ScopedResourceMetadata>()?.Resource;
            foreach (var method in endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? [])
            {
                sources.Add(new ActionSource(
                    new AccessMatrixAction($"{method} {path}", method, path, string.Join(" + ", required), resource),
                    required));
            }
        }

        return
        [
            .. sources
                .OrderBy(s => ResourceRank(s.Action.Resource))
                .ThenBy(s => s.Action.Path, StringComparer.Ordinal)
                .ThenBy(s => Array.IndexOf(MethodOrder, s.Action.Method)),
        ];
    }

    private static int ResourceRank(string? resource) => resource switch
    {
        ScopedResourceMetadata.Booking => 0,
        ScopedResourceMetadata.User => 1,
        _ => 2,
    };
}
