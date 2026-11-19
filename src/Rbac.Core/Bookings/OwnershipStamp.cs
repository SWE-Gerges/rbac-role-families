using Rbac.Abstractions;

namespace Rbac.Core.Bookings;

/// <summary>The ownership facts written onto a resource at creation time.</summary>
public sealed record OwnershipStamp(
    string TenantId,
    string OwnerUserId,
    RoleFamily? OwnerRoleFamily,
    string? AgencyId,
    string? CorporateId);

public enum StampFailure
{
    None,
    Anonymous,
    UnknownRole,
    MissingAgency,
    MissingCorporate,
}

public sealed record StampResult(OwnershipStamp? Stamp, StampFailure Failure)
{
    public bool Succeeded => Stamp is not null;
}

/// <summary>
/// Derives the ownership stamp for a new resource from the caller. Agency and corporate ids are only
/// stamped for the matching family, so a stray claim on another family cannot leak into a scope.
/// </summary>
public sealed class OwnershipStamper(IRoleCatalog catalog)
{
    public StampResult Stamp(Principal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (principal.IsAnonymous || string.IsNullOrWhiteSpace(principal.TenantId) || string.IsNullOrWhiteSpace(principal.UserId))
        {
            return new StampResult(null, StampFailure.Anonymous);
        }

        if (principal.Kind == PrincipalKind.Customer)
        {
            return new StampResult(new OwnershipStamp(principal.TenantId, principal.UserId, null, null, null), StampFailure.None);
        }

        var role = catalog.Find(principal.RoleKey);
        if (role is null)
        {
            return new StampResult(null, StampFailure.UnknownRole);
        }

        switch (role.Family)
        {
            case RoleFamily.Agency when string.IsNullOrWhiteSpace(principal.AgencyId):
                return new StampResult(null, StampFailure.MissingAgency);
            case RoleFamily.Corporate when string.IsNullOrWhiteSpace(principal.CorporateId):
                return new StampResult(null, StampFailure.MissingCorporate);
        }

        var agencyId = role.Family == RoleFamily.Agency ? principal.AgencyId : null;
        var corporateId = role.Family == RoleFamily.Corporate ? principal.CorporateId : null;
        return new StampResult(
            new OwnershipStamp(principal.TenantId, principal.UserId, role.Family, agencyId, corporateId),
            StampFailure.None);
    }
}
