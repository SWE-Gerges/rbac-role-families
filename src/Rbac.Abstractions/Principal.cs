namespace Rbac.Abstractions;

/// <summary>
/// The caller as seen by the scope layer, built from validated token claims. <see cref="UserId"/> is the effective user;
/// <see cref="ActingUser"/> is only set when a caller acts on behalf of another user.
/// </summary>
public sealed record Principal(
    PrincipalKind Kind,
    string UserId,
    string TenantId,
    string? RoleKey,
    string? AgencyId,
    string? CorporateId,
    int TokenVersion,
    string? ActingUser = null)
{
    public static Principal Anonymous { get; } = new(PrincipalKind.Anonymous, string.Empty, string.Empty, null, null, null, 0);

    public bool IsAnonymous => Kind == PrincipalKind.Anonymous;

    /// <summary>The user whose scope and permissions apply to the request.</summary>
    public string EffectiveUserId => UserId;

    /// <summary>The authenticated user who made the request. It differs from <see cref="EffectiveUserId"/> when acting on behalf of someone.</summary>
    public string ActingUserId => ActingUser ?? UserId;

    public bool IsOnBehalf => ActingUserId != UserId;

    public static Principal ForStaff(
        string userId, string tenantId, string roleKey, string? agencyId = null, string? corporateId = null, int tokenVersion = 1) =>
        new(PrincipalKind.Staff, userId, tenantId, roleKey, agencyId, corporateId, tokenVersion);

    public static Principal ForCustomer(string userId, string tenantId, int tokenVersion = 1) =>
        new(PrincipalKind.Customer, userId, tenantId, null, null, null, tokenVersion);
}
