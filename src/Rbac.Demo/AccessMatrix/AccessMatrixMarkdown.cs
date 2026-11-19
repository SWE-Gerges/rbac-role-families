using System.Text;
using Rbac.Abstractions;
using Rbac.Demo.Contracts;

namespace Rbac.Demo.AccessMatrix;

/// <summary>
/// Renders the access matrix as the markdown document committed at <c>docs/access-matrix.md</c>. Only the matrix itself goes
/// in, so the document and <c>GET /api/v1/access-matrix</c> are two views of one model. The one piece of prose that is not
/// derived is the legend explaining each strategy by name; rendering fails for a strategy that has no entry, so a new
/// strategy cannot appear in the matrix undocumented.
/// </summary>
internal static class AccessMatrixMarkdown
{
    public const string RegenerateCommand = "UPDATE_ACCESS_MATRIX=1 dotnet test --project tests/Rbac.IntegrationTests --filter \"FullyQualifiedName~AccessMatrixDocumentTests\"";

    private static readonly Dictionary<string, string> Legend = new(StringComparer.Ordinal)
    {
        ["SystemScope"] = "Every booking in the caller's tenant.",
        ["FinanceScope"] = "Bookings in refund-related statuses (RefundRequested, Refunded); the whole tenant when the caller also holds `reports.view`.",
        ["InternalScope"] = "Bookings written by internal staff and guest bookings in the tenant, never agency- or corporate-owned ones.",
        ["CorporateScope"] = "The caller's corporate account: all of it for a corporate admin or with `bookings.view-all-corporate`, otherwise only their own bookings. No corporate account, no rows.",
        ["AgencyScope"] = "The caller's agency: all of it for an agency admin or with `bookings.view-all-agency`, otherwise only their own bookings. No agency, no rows.",
        ["ViewerScope"] = "No booking rows.",
        ["CustomerScope"] = "The customer's own bookings.",
        ["NoAccessScope"] = "Nothing. The fail-closed fallback for anonymous callers and anything that cannot be resolved.",
        ["SystemUserScope"] = "Every user in the caller's tenant.",
        ["InternalUserScope"] = "Every user in the caller's tenant except members of the system family.",
        ["AgencyUserScope"] = "The users of the caller's own agency.",
        ["CorporateUserScope"] = "The users of the caller's own corporate account.",
        ["SelfUserScope"] = "Only the caller's own user record.",
        ["CrossAccountRoleManagement"] = "May manage, and act as, users of strictly lower standing anywhere in the tenant. Creates only roles listed for their role.",
        ["AccountRoleManagement"] = "Manages staff inside their own account. Only the founding admin creates or promotes admins, and nobody inside the account can delete or demote the founding admin.",
        ["DenyAllRoleManagement"] = "Manages nobody.",
    };

    public static string Render(AccessMatrixResponse matrix)
    {
        ArgumentNullException.ThrowIfNull(matrix);

        var builder = new StringBuilder();
        var staff = matrix.Rows.Where(r => r.Kind == PrincipalKind.Staff).ToList();

        builder.Append("# Access matrix\n\n");
        builder.Append("Generated from the role catalog, the scope and management strategy registries and the permission each endpoint declares. ");
        builder.Append("Do not edit it by hand: a test regenerates it in memory and fails when this file differs.\n\n");
        builder.Append($"Regenerate it with `{RegenerateCommand}` (see the README for the PowerShell form).\n\n");
        builder.Append("It shows **role defaults** only. Per-user grants and revokes, and edits made through the administration API, are not reflected here. ");
        builder.Append("Every tenant starts from these defaults and edits its own copy; `GET /api/v1/access-matrix` returns the same matrix computed from the caller's tenant's stored role defaults.\n\n");

        AppendFamilies(builder, matrix, staff);
        AppendLegend(builder, matrix);
        AppendEndpoints(builder, matrix);

        foreach (var (resource, heading) in new (string? Resource, string Heading)[]
                 {
                     (ScopedResourceMetadata.Booking, "Bookings"),
                     (ScopedResourceMetadata.User, "Users"),
                     (null, "Administration"),
                 })
        {
            AppendActionTable(builder, matrix, resource, heading);
        }

        AppendCreationGraph(builder, staff);
        AppendPermissions(builder, matrix);
        return builder.ToString();
    }

    private static void AppendFamilies(StringBuilder builder, AccessMatrixResponse matrix, List<AccessMatrixRow> staff)
    {
        builder.Append("## Families and strategies\n\n");
        builder.Append("| Family | Roles | Booking scope | User scope | Management |\n| --- | --- | --- | --- | --- |\n");
        foreach (var family in Enum.GetValues<RoleFamily>())
        {
            var members = staff.Where(r => r.Family == family).ToList();
            if (members.Count == 0)
            {
                continue;
            }

            builder.Append($"| {family} | {string.Join(", ", members.Select(r => $"`{r.Subject}`"))} | `{members[0].Scopes[ScopedResourceMetadata.Booking]}` | `{members[0].Scopes[ScopedResourceMetadata.User]}` | `{members[0].Management}` |\n");
        }

        foreach (var other in matrix.Rows.Where(r => r.Kind != PrincipalKind.Staff))
        {
            builder.Append($"| (not a family) | `{other.Subject}` | `{other.Scopes[ScopedResourceMetadata.Booking]}` | `{other.Scopes[ScopedResourceMetadata.User]}` | `{other.Management}` |\n");
        }

        builder.Append('\n');
    }

    private static void AppendLegend(StringBuilder builder, AccessMatrixResponse matrix)
    {
        var names = matrix.Rows
            .SelectMany(r => r.Scopes.Values.Append(r.Management))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToList();

        builder.Append("## What each strategy does\n\n");
        foreach (var name in names)
        {
            if (!Legend.TryGetValue(name, out var text))
            {
                throw new InvalidOperationException($"The access matrix uses the strategy '{name}', which has no entry in the legend of {nameof(AccessMatrixMarkdown)}.");
            }

            builder.Append($"- `{name}`: {text}\n");
        }

        builder.Append('\n');
    }

    private static void AppendEndpoints(StringBuilder builder, AccessMatrixResponse matrix)
    {
        builder.Append("## Endpoints and the permission each requires\n\n");
        builder.Append("| Method | Path | Required permission | Rows reached through |\n| --- | --- | --- | --- |\n");
        foreach (var action in matrix.Actions)
        {
            builder.Append($"| {action.Method} | `{action.Path}` | `{action.Permission}` | {(action.Resource is null ? "-" : $"{action.Resource} scope")} |\n");
        }

        builder.Append("\nEvery other endpoint is either anonymous (health, the demo token issuer) or open to any authenticated caller (`/api/v1/me`, the OpenAPI document).\n\n");
    }

    private static void AppendActionTable(StringBuilder builder, AccessMatrixResponse matrix, string? resource, string heading)
    {
        var actions = matrix.Actions.Where(a => a.Resource == resource).ToList();
        if (actions.Count == 0)
        {
            return;
        }

        builder.Append($"## {heading}\n\n");
        builder.Append(resource is null
            ? "`yes` when the role holds the required permission by default.\n\n"
            : $"`yes` when the role holds the required permission by default. The scope column says which rows that permission reaches ({resource}).\n\n");

        var header = new StringBuilder("| Subject |");
        var rule = new StringBuilder("| --- |");
        if (resource is not null)
        {
            header.Append(" Scope |");
            rule.Append(" --- |");
        }

        foreach (var action in actions)
        {
            header.Append($" {action.Method} {Short(action.Path)} |");
            rule.Append(" --- |");
        }

        builder.Append(header).Append('\n').Append(rule).Append('\n');
        foreach (var row in matrix.Rows)
        {
            builder.Append($"| `{row.Subject}` |");
            if (resource is not null)
            {
                builder.Append($" `{row.Scopes[resource]}` |");
            }

            foreach (var action in actions)
            {
                builder.Append(row.Allowed[action.Id] ? " yes |" : " - |");
            }

            builder.Append('\n');
        }

        builder.Append('\n');
    }

    private static void AppendCreationGraph(StringBuilder builder, List<AccessMatrixRow> staff)
    {
        builder.Append("## Creation graph\n\n");
        builder.Append("Who may create which roles. Account-bound roles are created inside the creator's own account only, and only the founding admin of an account creates further admins.\n\n");
        builder.Append("| Role | Tier | Can create |\n| --- | --- | --- |\n");
        foreach (var row in staff)
        {
            builder.Append($"| `{row.Subject}` | {(row.IsAdmin ? "admin" : "staff")} | {(row.CanCreate.Count == 0 ? "-" : string.Join(", ", row.CanCreate.Select(r => $"`{r}`")))} |\n");
        }

        builder.Append('\n');
    }

    private static void AppendPermissions(StringBuilder builder, AccessMatrixResponse matrix)
    {
        builder.Append("## Permissions\n\n");
        builder.Append("| Permission | Description | Reserved | Held by default by |\n| --- | --- | --- | --- |\n");
        foreach (var permission in matrix.Permissions)
        {
            var holders = matrix.Rows
                .Where(r => r.DefaultPermissions.Contains(permission.Key, StringComparer.Ordinal))
                .Select(r => $"`{r.Subject}`")
                .ToList();
            builder.Append($"| `{permission.Key}` | {permission.Description} | {(permission.Reserved ? "yes" : "-")} | {(holders.Count == 0 ? "-" : string.Join(", ", holders))} |\n");
        }
    }

    private static string Short(string path) => path.StartsWith("/api/v1", StringComparison.Ordinal) ? path["/api/v1".Length..] : path;
}
