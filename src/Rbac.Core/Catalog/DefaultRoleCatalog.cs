using Rbac.Abstractions;

namespace Rbac.Core.Catalog;

/// <summary>The role catalog used by the demo: nine staff roles across the six families.</summary>
public static class DefaultRoleCatalog
{
    /// <summary>Version 1 shipped the booking roles; version 2 added user management, permission administration and audit.</summary>
    public const int Version = 2;

    public static RoleCatalog Create() => RoleCatalog.Create()
        .Version(Version)
        .Role(RoleKeys.SystemAdmin, RoleFamily.System, r => r
            .Admin()
            .Grants(
                Permissions.BookingsRead,
                Permissions.BookingsCreate,
                Permissions.BookingsCancel,
                Permissions.ReportsView,
                Permissions.UsersRead,
                Permissions.UsersCreate,
                Permissions.UsersManage,
                Permissions.UsersActOnBehalf,
                Permissions.PermissionsView,
                Permissions.RolesManagePermissions,
                Permissions.AuditView,
                Permissions.AccessMatrixView)
            .CanCreate(
                RoleKeys.FinanceOfficer,
                RoleKeys.InternalAdmin,
                RoleKeys.InternalStaff,
                RoleKeys.CorporateAdmin,
                RoleKeys.CorporateStaff,
                RoleKeys.AgencyAdmin,
                RoleKeys.AgencyStaff,
                RoleKeys.ReportViewer))
        .Role(RoleKeys.FinanceOfficer, RoleFamily.Finance, r => r
            .Grants(Permissions.BookingsRead))
        .Role(RoleKeys.InternalAdmin, RoleFamily.Internal, r => r
            .Admin()
            .Grants(
                Permissions.BookingsRead,
                Permissions.BookingsCreate,
                Permissions.BookingsCancel,
                Permissions.ReportsView,
                Permissions.UsersRead,
                Permissions.UsersCreate,
                Permissions.UsersManage,
                Permissions.UsersActOnBehalf,
                Permissions.PermissionsView,
                Permissions.AuditView)
            .CanCreate(RoleKeys.InternalStaff, RoleKeys.CorporateAdmin, RoleKeys.AgencyAdmin, RoleKeys.ReportViewer))
        .Role(RoleKeys.InternalStaff, RoleFamily.Internal, r => r
            .Grants(Permissions.BookingsRead, Permissions.BookingsCreate, Permissions.BookingsCancel))
        .Role(RoleKeys.CorporateAdmin, RoleFamily.Corporate, r => r
            .Admin()
            .Grants(
                Permissions.BookingsRead,
                Permissions.BookingsCreate,
                Permissions.BookingsCancel,
                Permissions.BookingsViewAllCorporate,
                Permissions.UsersRead,
                Permissions.UsersCreate,
                Permissions.UsersManage,
                Permissions.PermissionsView)
            .CanCreate(RoleKeys.CorporateAdmin, RoleKeys.CorporateStaff))
        .Role(RoleKeys.CorporateStaff, RoleFamily.Corporate, r => r
            .Grants(Permissions.BookingsRead, Permissions.BookingsCreate, Permissions.BookingsCancel))
        .Role(RoleKeys.AgencyAdmin, RoleFamily.Agency, r => r
            .Admin()
            .Grants(
                Permissions.BookingsRead,
                Permissions.BookingsCreate,
                Permissions.BookingsCancel,
                Permissions.BookingsViewAllAgency,
                Permissions.UsersRead,
                Permissions.UsersCreate,
                Permissions.UsersManage,
                Permissions.PermissionsView)
            .CanCreate(RoleKeys.AgencyAdmin, RoleKeys.AgencyStaff))
        .Role(RoleKeys.AgencyStaff, RoleFamily.Agency, r => r
            .Grants(Permissions.BookingsRead, Permissions.BookingsCreate, Permissions.BookingsCancel))
        .Role(RoleKeys.ReportViewer, RoleFamily.Viewer, r => r
            .Grants(Permissions.ReportsView))
        .Build();
}
