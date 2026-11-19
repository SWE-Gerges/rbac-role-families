namespace Rbac.Core.Catalog;

public sealed record PermissionDefinition(string Key, string Description);

/// <summary>The only place permission literals are written down.</summary>
public static class Permissions
{
    public const string BookingsRead = "bookings.read";
    public const string BookingsCreate = "bookings.create";
    public const string BookingsCancel = "bookings.cancel";
    public const string BookingsViewAllAgency = "bookings.view-all-agency";
    public const string BookingsViewAllCorporate = "bookings.view-all-corporate";
    public const string ReportsView = "reports.view";
    public const string UsersRead = "users.read";
    public const string UsersCreate = "users.create";
    public const string UsersManage = "users.manage";
    public const string UsersActOnBehalf = "users.act-on-behalf";
    public const string PermissionsView = "permissions.view";
    public const string RolesManagePermissions = "roles.manage-permissions";
    public const string AuditView = "audit.view";
    public const string AccessMatrixView = "access-matrix.view";

    public static IReadOnlyList<PermissionDefinition> Definitions { get; } =
    [
        new(BookingsRead, "Read bookings inside the caller's scope"),
        new(BookingsCreate, "Create bookings"),
        new(BookingsCancel, "Cancel bookings inside the caller's scope"),
        new(BookingsViewAllAgency, "See every booking of the caller's agency, not only their own"),
        new(BookingsViewAllCorporate, "See every booking of the caller's corporate account, not only their own"),
        new(ReportsView, "View reports"),
        new(UsersRead, "List and read users inside the caller's scope"),
        new(UsersCreate, "Create users the caller's role may create"),
        new(UsersManage, "Change roles, delete users and edit their permissions inside the caller's management scope"),
        new(UsersActOnBehalf, "Act on behalf of a user of lower privilege"),
        new(PermissionsView, "View the permission catalog and role definitions"),
        new(RolesManagePermissions, "Edit the default permissions of a role (system administrators only)"),
        new(AuditView, "View the audit trail of the caller's tenant"),
        new(AccessMatrixView, "View the role by action access matrix"),
    ];

    public static IReadOnlyList<string> All { get; } = [.. Definitions.Select(d => d.Key)];

    /// <summary>
    /// Permissions that can never be given to a user individually, only through a role. Editing role defaults is
    /// reserved to the system family, so it must not be delegable by a grant.
    /// </summary>
    public static IReadOnlyList<string> Reserved { get; } = [RolesManagePermissions];

    /// <summary>What a customer may do. Customers are not staff, so they have no role in the catalog.</summary>
    public static IReadOnlyList<string> CustomerDefaults { get; } = [BookingsRead, BookingsCreate, BookingsCancel];

    public static string Describe(string key) => Definitions.FirstOrDefault(d => d.Key == key)?.Description ?? key;
}
