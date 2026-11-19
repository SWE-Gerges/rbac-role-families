using Rbac.Abstractions;
using Rbac.Core.Catalog;

namespace Rbac.Tests.Support;

internal static class Principals
{
    public static Principal Staff(string userId, string roleKey, string? agencyId = null, string? corporateId = null, string tenantId = ScopeDataset.TenantA) =>
        Principal.ForStaff(userId, tenantId, roleKey, agencyId, corporateId);

    public static Principal SystemAdmin(string tenantId = ScopeDataset.TenantA) => Staff("u-system", RoleKeys.SystemAdmin, tenantId: tenantId);

    public static Principal InternalStaff() => Staff("u-internal", RoleKeys.InternalStaff);

    public static Principal AgencyAdmin(string? agencyId = "ag1") => Staff("u-agency-admin", RoleKeys.AgencyAdmin, agencyId: agencyId);

    public static Principal AgencyStaff(string? agencyId = "ag1") => Staff("u-agency-staff", RoleKeys.AgencyStaff, agencyId: agencyId);

    public static Principal CorporateAdmin(string? corporateId = "co1") => Staff("u-corp-admin", RoleKeys.CorporateAdmin, corporateId: corporateId);

    public static Principal CorporateStaff(string? corporateId = "co1") => Staff("u-corp-staff", RoleKeys.CorporateStaff, corporateId: corporateId);

    public static Principal Finance() => Staff("u-finance", RoleKeys.FinanceOfficer);

    public static Principal Viewer() => Staff("u-viewer", RoleKeys.ReportViewer);

    public static Principal Customer(string tenantId = ScopeDataset.TenantA) => Principal.ForCustomer("u-customer", tenantId);
}
