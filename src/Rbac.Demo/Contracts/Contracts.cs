using System.ComponentModel.DataAnnotations;
using Rbac.Abstractions;
using Rbac.Core.Bookings;

namespace Rbac.Demo.Contracts;

public sealed record DevTokenRequest([property: Required] string UserId);

public sealed record DevTokenResponse(
    string AccessToken,
    string TokenType,
    DateTimeOffset ExpiresAt,
    string UserId,
    string TenantId,
    PrincipalKind Kind,
    string? RoleKey);

public sealed record BookingResponse(
    string Id,
    string TenantId,
    string OwnerUserId,
    RoleFamily? OwnerRoleFamilyAtCreation,
    string? AgencyId,
    string? CorporateId,
    bool IsGuestBooking,
    BookingType Type,
    BookingStatus Status,
    decimal Amount,
    DateTimeOffset CreatedAt);

/// <param name="ChannelHint">The client channel header echoed for presentation. It never influences what is returned.</param>
public sealed record BookingListResponse(
    IReadOnlyList<BookingResponse> Items,
    int Page,
    int PageSize,
    int TotalCount,
    string? ChannelHint);

public sealed record CreateBookingRequest(BookingType Type, decimal Amount);

/// <param name="ActingUserId">Set when the caller sent X-On-Behalf-Of: the authenticated user who is acting as <paramref name="UserId"/>.</param>
public sealed record MeResponse(
    PrincipalKind Kind,
    string? UserId,
    string? TenantId,
    string? RoleKey,
    RoleFamily? Family,
    string? AgencyId,
    string? CorporateId,
    int TokenVersion,
    IReadOnlyList<string> Permissions,
    string? ActingUserId = null);

/// <param name="Id">Method and path, for example <c>GET /api/v1/bookings</c>.</param>
/// <param name="Permission">The permission the endpoint requires (several are joined with <c> + </c>).</param>
/// <param name="Resource">The resource whose scope strategy decides which rows the endpoint reaches, if any.</param>
public sealed record AccessMatrixAction(string Id, string Method, string Path, string Permission, string? Resource);

public sealed record AccessMatrixPermission(string Key, string Description, bool Reserved);

/// <param name="Subject">A role key, or <c>customer</c> or <c>anonymous</c>.</param>
/// <param name="Scopes">The scope strategy per resource.</param>
/// <param name="Management">The role management strategy of the subject's family.</param>
/// <param name="CanCreate">The roles this role may create.</param>
/// <param name="DefaultPermissions">The stored default permissions of the role.</param>
/// <param name="Allowed">For every action id, whether the role holds the required permission by default.</param>
public sealed record AccessMatrixRow(
    string Subject,
    PrincipalKind Kind,
    RoleFamily? Family,
    bool IsAdmin,
    IReadOnlyDictionary<string, string> Scopes,
    string Management,
    IReadOnlyList<string> CanCreate,
    IReadOnlyList<string> DefaultPermissions,
    IReadOnlyDictionary<string, bool> Allowed);

public sealed record AccessMatrixResponse(
    IReadOnlyList<AccessMatrixAction> Actions,
    IReadOnlyList<AccessMatrixPermission> Permissions,
    IReadOnlyList<AccessMatrixRow> Rows);

public sealed record CreateUserRequest(string Handle, string DisplayName, string RoleKey, string? AgencyId = null, string? CorporateId = null);

public sealed record ChangeRoleRequest(string RoleKey, string? AgencyId = null, string? CorporateId = null);

/// <param name="PermissionsVersion">Changes with every permission edit; send it back as <c>If-Match</c> when editing permissions.</param>
public sealed record UserResponse(
    string Id,
    string TenantId,
    string Handle,
    string DisplayName,
    PrincipalKind Kind,
    string? RoleKey,
    RoleFamily? Family,
    string? AgencyId,
    string? CorporateId,
    bool IsFoundingAdmin,
    int PermissionsVersion);

public sealed record UserListResponse(IReadOnlyList<UserResponse> Items, int Page, int PageSize, int TotalCount);

public sealed record PermissionResponse(string Key, string Description, bool Reserved);

public sealed record RoleResponse(
    string Key,
    RoleFamily Family,
    bool IsAdmin,
    IReadOnlyList<string> Permissions,
    IReadOnlyList<string> CreatableRoleKeys);

/// <param name="Permissions">The complete list of default permissions the role should have afterwards.</param>
public sealed record SetRolePermissionsRequest(IReadOnlyList<string>? Permissions);

/// <param name="Version">Also sent as the <c>ETag</c> header; send it back as <c>If-Match</c> when editing.</param>
public sealed record UserPermissionsResponse(
    string UserId,
    string? RoleKey,
    int Version,
    IReadOnlyList<string> RoleDefaults,
    IReadOnlyList<string> Grants,
    IReadOnlyList<string> Revokes,
    IReadOnlyList<string> Effective);

/// <param name="Grant">Make these permissions effective for the user.</param>
/// <param name="Revoke">Make these permissions not effective for the user.</param>
/// <param name="Reset">Remove any override so the role default applies again.</param>
public sealed record EditUserPermissionsRequest(
    IReadOnlyList<string>? Grant = null,
    IReadOnlyList<string>? Revoke = null,
    IReadOnlyList<string>? Reset = null);

/// <param name="ActorUserId">The authenticated user who made the request.</param>
/// <param name="EffectiveUserId">Set only when the actor acted on behalf of another user.</param>
/// <param name="Before">What the target looked like before the change, as recorded.</param>
/// <param name="After">What the target looks like after the change, as recorded.</param>
public sealed record AuditEntryResponse(
    string Id,
    string TenantId,
    string ActorUserId,
    string? EffectiveUserId,
    string Action,
    string TargetType,
    string TargetId,
    System.Text.Json.JsonElement? Before,
    System.Text.Json.JsonElement? After,
    string? CorrelationId,
    DateTimeOffset At);

public sealed record AuditListResponse(IReadOnlyList<AuditEntryResponse> Items, int Page, int PageSize, int TotalCount);
