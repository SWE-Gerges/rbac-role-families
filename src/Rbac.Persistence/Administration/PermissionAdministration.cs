using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Rbac.Abstractions;
using Rbac.Core.Catalog;
using Rbac.Core.Management;
using Rbac.Persistence.Entities;

namespace Rbac.Persistence.Administration;

public sealed record PermissionView(string Key, string Description, bool Reserved);

public sealed record RoleView(
    string Key,
    RoleFamily Family,
    bool IsAdmin,
    IReadOnlyList<string> Permissions,
    IReadOnlyList<string> CreatableRoleKeys);

/// <param name="Version">Send it back as <c>If-Match</c> when editing; it changes with every permission change.</param>
public sealed record UserPermissionsView(
    string UserId,
    string? RoleKey,
    int Version,
    IReadOnlyList<string> RoleDefaults,
    IReadOnlyList<string> Grants,
    IReadOnlyList<string> Revokes,
    IReadOnlyList<string> Effective);

/// <summary>
/// The permission catalog, role defaults and per-user overrides. Role defaults belong to the caller's tenant: every read and
/// write names that tenant, so an administrator can neither see nor change another tenant's defaults. Reads come from the
/// stored rows, never from the catalog held in memory, so they stay right after an edit. Every write is one transaction holding the change, the session
/// revocation for the users it touches and the audit entry. Callers can touch only permissions they hold (the grant
/// ceiling), and per-user edits only inside their management scope.
/// </summary>
public sealed class PermissionAdministration(
    RbacDbContext db,
    IPrincipalContext principalContext,
    ManagementSupport support,
    ICurrentPermissions currentPermissions,
    RoleManagementResolver management,
    IRoleCatalog catalog,
    IAuditLog audit)
{
    private string TenantId => principalContext.Current.TenantId;

    public async Task<IReadOnlyList<PermissionView>> ListPermissionsAsync(CancellationToken cancellationToken) =>
        [.. (await db.Permissions.AsNoTracking().OrderBy(p => p.Key).ToListAsync(cancellationToken))
            .Select(p => new PermissionView(p.Key, p.Description, Permissions.Reserved.Contains(p.Key)))];

    public async Task<IReadOnlyList<RoleView>> ListRolesAsync(CancellationToken cancellationToken)
    {
        var stored = await RoleCatalogStore.LoadAsync(db, TenantId, cancellationToken);
        return [.. stored.Roles.Select(ToView)];
    }

    public async Task<AdminResult<RoleView>> GetRoleAsync(string key, CancellationToken cancellationToken)
    {
        var stored = await RoleCatalogStore.LoadAsync(db, TenantId, cancellationToken);
        return stored.Find(key) is { } role ? AdminResult<RoleView>.Ok(ToView(role)) : AdminResult<RoleView>.NotFound();
    }

    /// <summary>
    /// Replaces the default permissions of a role in the caller's tenant. Only that tenant is affected: its holders of the role
    /// have their sessions revoked and its epoch moves. The caller must hold every permission they add or remove.
    /// </summary>
    public async Task<AdminResult<RoleView>> SetRolePermissionsAsync(
        string key, IReadOnlyCollection<string>? requested, CancellationToken cancellationToken)
    {
        if (!await db.Roles.AsNoTracking().AnyAsync(r => r.Key == key, cancellationToken))
        {
            return AdminResult<RoleView>.NotFound();
        }

        if (requested is null)
        {
            return AdminResult<RoleView>.Invalid("permissions", "The permissions list is required.");
        }

        var wanted = requested.Distinct(StringComparer.Ordinal).ToHashSet(StringComparer.Ordinal);
        var unknown = await UnknownAsync(wanted, cancellationToken);
        if (unknown.Count > 0)
        {
            return AdminResult<RoleView>.Invalid("permissions", $"Unknown permissions: {string.Join(", ", unknown)}.");
        }

        var tenantId = TenantId;
        var rows = await db.RolePermissions
            .IgnoreQueryFilters()
            .Where(rp => rp.TenantId == tenantId && rp.RoleKey == key)
            .ToListAsync(cancellationToken);
        var current = rows.Select(r => r.PermissionKey).ToHashSet(StringComparer.Ordinal);
        var added = wanted.Except(current).Order(StringComparer.Ordinal).ToArray();
        var removed = current.Except(wanted).Order(StringComparer.Ordinal).ToArray();

        var held = await currentPermissions.GetAsync(cancellationToken);
        var violations = GrantCeiling.Check(held, added.Concat(removed));
        if (violations.Count > 0)
        {
            return AdminResult<RoleView>.Forbidden(Describe(violations));
        }

        if (added.Length + removed.Length > 0)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            db.RolePermissions.RemoveRange(rows.Where(r => removed.Contains(r.PermissionKey)));
            db.RolePermissions.AddRange(added.Select(p => new RolePermissionEntity { TenantId = tenantId, RoleKey = key, PermissionKey = p }));

            await PermissionChangeEffects.RoleDefaultsChangedAsync(db, tenantId, key, cancellationToken);
            audit.Append(new AuditRecord(
                "role.permissions-changed",
                "Role",
                key,
                Before: new { Permissions = current.Order(StringComparer.Ordinal).ToArray() },
                After: new { Permissions = wanted.Order(StringComparer.Ordinal).ToArray() }));
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }

        return await GetRoleAsync(key, cancellationToken);
    }

    public async Task<AdminResult<UserPermissionsView>> GetUserPermissionsAsync(string userId, CancellationToken cancellationToken)
    {
        var target = await support.FindVisibleAsync(principalContext.Current, userId, track: false, cancellationToken);
        return target is null
            ? AdminResult<UserPermissionsView>.NotFound()
            : AdminResult<UserPermissionsView>.Ok(await ViewAsync(target.Id, target.RoleKey, target.Kind, target.PermissionsVersion, cancellationToken));
    }

    /// <summary>
    /// Applies a grant, revoke and reset diff to one user. Precedence: visibility (404), validation (400), management rule
    /// (403), grant ceiling (403), then the version precondition (428 when missing, 412 when stale).
    /// </summary>
    public async Task<AdminResult<UserPermissionsView>> EditUserPermissionsAsync(
        string userId, string? ifMatch, PermissionDiffRequest diff, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(diff);
        var principal = principalContext.Current;

        var target = await support.FindVisibleAsync(principal, userId, track: false, cancellationToken);
        if (target is null)
        {
            return AdminResult<UserPermissionsView>.NotFound();
        }

        var duplicates = PermissionDiffer.Duplicates(diff);
        if (duplicates.Count > 0)
        {
            return AdminResult<UserPermissionsView>.Invalid("permissions", $"A permission can appear in one list only: {string.Join(", ", duplicates)}.");
        }

        var unknown = await UnknownAsync(diff.Touched.ToHashSet(StringComparer.Ordinal), cancellationToken);
        if (unknown.Count > 0)
        {
            return AdminResult<UserPermissionsView>.Invalid("permissions", $"Unknown permissions: {string.Join(", ", unknown)}.");
        }

        var actor = await support.ResolveActorAsync(principal, cancellationToken);
        if (actor is null)
        {
            return AdminResult<UserPermissionsView>.Forbidden("Your role cannot manage users.");
        }

        var decision = management.StrategyFor(principal).Evaluate(
            actor,
            new ManagementRequest(ManagementOperation.EditPermissions, ManagementSupport.ToManaged(target)),
            catalog);
        if (!decision.Allowed)
        {
            return AdminResult<UserPermissionsView>.Forbidden(decision.Reason!);
        }

        var held = await currentPermissions.GetAsync(cancellationToken);
        var violations = GrantCeiling.Check(held, diff.Touched);
        if (violations.Count > 0)
        {
            return AdminResult<UserPermissionsView>.Forbidden(Describe(violations));
        }

        if (string.IsNullOrWhiteSpace(ifMatch))
        {
            return new AdminResult<UserPermissionsView>(AdminOutcome.PreconditionRequired);
        }

        if (!TryParseVersion(ifMatch, out var expected) || expected != target.PermissionsVersion)
        {
            return new AdminResult<UserPermissionsView>(AdminOutcome.PreconditionFailed);
        }

        var roleDefaults = await DefaultsAsync(target.RoleKey, target.Kind, cancellationToken);
        var rows = await db.UserPermissions.Where(up => up.UserId == target.Id).ToListAsync(cancellationToken);
        var before = rows.ToDictionary(r => r.PermissionKey, r => r.Effect == PermissionEffect.Grant, StringComparer.Ordinal);
        var result = PermissionDiffer.Apply(roleDefaults.ToHashSet(StringComparer.Ordinal), before, diff);

        if (!result.HasChanges)
        {
            return AdminResult<UserPermissionsView>.Ok(await ViewAsync(target.Id, target.RoleKey, target.Kind, target.PermissionsVersion, cancellationToken));
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // Compare and swap: the write only counts if nobody changed this user's permissions since the version the client read.
        var swapped = await db.Users
            .Where(u => u.Id == target.Id && u.PermissionsVersion == expected)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.PermissionsVersion, expected + 1), cancellationToken);
        if (swapped == 0)
        {
            return new AdminResult<UserPermissionsView>(AdminOutcome.PreconditionFailed);
        }

        foreach (var permission in result.Changed)
        {
            var existing = rows.SingleOrDefault(r => r.PermissionKey == permission);
            if (result.Overrides.TryGetValue(permission, out var grant))
            {
                var effect = grant ? PermissionEffect.Grant : PermissionEffect.Revoke;
                if (existing is null)
                {
                    db.UserPermissions.Add(new UserPermissionEntity { TenantId = target.TenantId, UserId = target.Id, PermissionKey = permission, Effect = effect });
                }
                else
                {
                    existing.Effect = effect;
                }
            }
            else if (existing is not null)
            {
                db.UserPermissions.Remove(existing);
            }
        }

        await PermissionChangeEffects.UserChangedAsync(db, target.TenantId, target.Id, cancellationToken);
        audit.Append(new AuditRecord(
            "user.permissions-changed",
            "User",
            target.Id,
            Before: Overrides(before, roleDefaults),
            After: Overrides(result.Overrides, roleDefaults)));
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return AdminResult<UserPermissionsView>.Ok(await ViewAsync(target.Id, target.RoleKey, target.Kind, expected + 1, cancellationToken));
    }

    private static object Overrides(IReadOnlyDictionary<string, bool> overrides, IEnumerable<string> roleDefaults) => new
    {
        Grants = overrides.Where(o => o.Value).Select(o => o.Key).Order(StringComparer.Ordinal).ToArray(),
        Revokes = overrides.Where(o => !o.Value).Select(o => o.Key).Order(StringComparer.Ordinal).ToArray(),
        Effective = PermissionDiffer.Effective(roleDefaults, overrides),
    };

    private async Task<UserPermissionsView> ViewAsync(
        string userId, string? roleKey, PrincipalKind kind, int version, CancellationToken cancellationToken)
    {
        var defaults = await DefaultsAsync(roleKey, kind, cancellationToken);
        var overrides = (await db.UserPermissions.AsNoTracking().Where(up => up.UserId == userId).ToListAsync(cancellationToken))
            .ToDictionary(r => r.PermissionKey, r => r.Effect == PermissionEffect.Grant, StringComparer.Ordinal);

        return new UserPermissionsView(
            userId,
            roleKey,
            version,
            [.. defaults.Order(StringComparer.Ordinal)],
            [.. overrides.Where(o => o.Value).Select(o => o.Key).Order(StringComparer.Ordinal)],
            [.. overrides.Where(o => !o.Value).Select(o => o.Key).Order(StringComparer.Ordinal)],
            PermissionDiffer.Effective(defaults, overrides));
    }

    private async Task<IReadOnlyList<string>> DefaultsAsync(string? roleKey, PrincipalKind kind, CancellationToken cancellationToken)
    {
        if (kind == PrincipalKind.Customer)
        {
            return Permissions.CustomerDefaults;
        }

        var tenantId = TenantId;
        return await db.RolePermissions
            .IgnoreQueryFilters()
            .AsNoTracking()
            .Where(rp => rp.TenantId == tenantId && rp.RoleKey == roleKey)
            .Select(rp => rp.PermissionKey)
            .ToListAsync(cancellationToken);
    }

    private async Task<IReadOnlyList<string>> UnknownAsync(IReadOnlySet<string> requested, CancellationToken cancellationToken)
    {
        if (requested.Count == 0)
        {
            return [];
        }

        var known = await db.Permissions.AsNoTracking().Select(p => p.Key).ToListAsync(cancellationToken);
        return [.. requested.Except(known, StringComparer.Ordinal).Order(StringComparer.Ordinal)];
    }

    private static RoleView ToView(RoleDefinition role) => new(
        role.Key,
        role.Family,
        role.IsAdmin,
        [.. role.DefaultPermissions.Order(StringComparer.Ordinal)],
        role.CreatableRoleKeys);

    private static string Describe(IReadOnlyList<CeilingViolation> violations) =>
        string.Join(" ", violations.Select(v => $"{v.Permission}: {v.Reason}"));

    /// <summary>Accepts the version as the client got it from the ETag header: a number, optionally quoted or weak.</summary>
    private static bool TryParseVersion(string header, out int version)
    {
        var text = header.Trim();
        if (text.StartsWith("W/", StringComparison.Ordinal))
        {
            text = text[2..];
        }

        return int.TryParse(text.Trim('"'), NumberStyles.None, CultureInfo.InvariantCulture, out version);
    }
}
