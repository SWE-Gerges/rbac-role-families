namespace Rbac.AspNetCore.Claims;

/// <summary>Claim names used in tokens. Short names, so token mapping must keep them as they are.</summary>
public static class RbacClaimTypes
{
    public const string Subject = "sub";
    public const string TenantId = "tenant_id";
    public const string Role = "role";
    public const string AgencyId = "agency_id";
    public const string CorporateId = "corporate_id";
    public const string TokenVersion = "token_version";
    public const string PrincipalKind = "principal_kind";

    public const string StaffKind = "staff";
    public const string CustomerKind = "customer";
}
