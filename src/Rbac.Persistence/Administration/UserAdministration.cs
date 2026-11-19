using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Rbac.Abstractions;
using Rbac.Core.Management;
using Rbac.Core.Users;

namespace Rbac.Persistence.Administration;

public sealed record CreateUserCommand(string Handle, string DisplayName, string RoleKey, string? AgencyId, string? CorporateId);

public sealed record ChangeRoleCommand(string RoleKey, string? AgencyId, string? CorporateId);

/// <summary>
/// Creates, re-roles and soft deletes users. Every operation runs in one transaction that holds the change, its audit
/// entry and the token version bump, so a session is never revoked without the change that caused it (or the reverse).
/// Who may do what is decided by the caller's role management strategy; which users the caller can see at all is decided
/// by the user scope strategy, so an invisible user is a 404.
/// </summary>
public sealed partial class UserAdministration(
    RbacDbContext db,
    IPrincipalContext principalContext,
    ManagementSupport support,
    IRoleCatalog catalog,
    RoleManagementResolver management,
    IAuditLog audit,
    TimeProvider clock)
{
    [GeneratedRegex("^[a-z0-9][a-z0-9._-]{1,62}$")]
    private static partial Regex HandlePattern();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
    private static partial Regex AccountPattern();

    public async Task<AdminResult<User>> CreateAsync(CreateUserCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var principal = principalContext.Current;
        var handle = command.Handle ?? string.Empty;

        var errors = new Dictionary<string, string[]>();
        if (!HandlePattern().IsMatch(handle))
        {
            errors["handle"] = ["The handle must be 2 to 63 characters: lower case letters, digits, '.', '_' or '-', starting with a letter or digit."];
        }

        if (string.IsNullOrWhiteSpace(command.DisplayName) || command.DisplayName.Length > 200)
        {
            errors["displayName"] = ["The display name is required and at most 200 characters."];
        }

        var newRole = catalog.Find(command.RoleKey);
        if (newRole is null)
        {
            errors["roleKey"] = ["That role does not exist."];
        }

        if (errors.Count > 0)
        {
            return new AdminResult<User>(AdminOutcome.Invalid, Errors: errors);
        }

        var callerRole = catalog.Find(principal.RoleKey);
        var accounts = ResolveAccounts(callerRole, principal, newRole!, command.AgencyId, command.CorporateId, current: null);
        if (accounts.Error is { } accountError)
        {
            return new AdminResult<User>(AdminOutcome.Invalid, Errors: accountError);
        }

        var actor = await support.ResolveActorAsync(principal, cancellationToken);
        if (actor is null)
        {
            return AdminResult<User>.Forbidden("Your role cannot manage users.");
        }

        var decision = management.StrategyFor(principal).Evaluate(
            actor,
            new ManagementRequest(ManagementOperation.Create, NewRole: newRole, AgencyId: accounts.AgencyId, CorporateId: accounts.CorporateId),
            catalog);
        if (!decision.Allowed)
        {
            return AdminResult<User>.Forbidden(decision.Reason!);
        }

        if (await db.Users.AnyAsync(u => u.Handle == handle, cancellationToken))
        {
            return AdminResult<User>.Conflict("That handle is already used by another user.");
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var user = new User
        {
            Id = $"usr-{Guid.CreateVersion7():N}",
            TenantId = principal.TenantId,
            Handle = handle,
            DisplayName = command.DisplayName.Trim(),
            Kind = PrincipalKind.Staff,
            RoleKey = newRole!.Key,
            AgencyId = accounts.AgencyId,
            CorporateId = accounts.CorporateId,
            IsFoundingAdmin = await BecomesFoundingAdminAsync(newRole, accounts.AgencyId, accounts.CorporateId, excludedUserId: null, cancellationToken),
        };
        db.Users.Add(user);
        audit.Append(new AuditRecord("user.created", "User", user.Id, After: Snapshot(user)));

        var conflict = await SaveAsync(cancellationToken);
        if (conflict is not null)
        {
            return AdminResult<User>.Conflict(conflict);
        }

        await transaction.CommitAsync(cancellationToken);
        return AdminResult<User>.Created(user);
    }

    public async Task<AdminResult<User>> ChangeRoleAsync(string id, ChangeRoleCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var principal = principalContext.Current;

        var target = await support.FindVisibleAsync(principal, id, track: true, cancellationToken);
        if (target is null)
        {
            return AdminResult<User>.NotFound();
        }

        var newRole = catalog.Find(command.RoleKey);
        if (newRole is null)
        {
            return AdminResult<User>.Invalid("roleKey", "That role does not exist.");
        }

        if (target.Kind != PrincipalKind.Staff)
        {
            return AdminResult<User>.Invalid("roleKey", "Only staff users have a role.");
        }

        var callerRole = catalog.Find(principal.RoleKey);
        var accounts = ResolveAccounts(callerRole, principal, newRole, command.AgencyId, command.CorporateId, current: target);
        if (accounts.Error is { } accountError)
        {
            return new AdminResult<User>(AdminOutcome.Invalid, Errors: accountError);
        }

        var actor = await support.ResolveActorAsync(principal, cancellationToken);
        if (actor is null)
        {
            return AdminResult<User>.Forbidden("Your role cannot manage users.");
        }

        var decision = management.StrategyFor(principal).Evaluate(
            actor,
            new ManagementRequest(ManagementOperation.ChangeRole, ManagementSupport.ToManaged(target), newRole, accounts.AgencyId, accounts.CorporateId),
            catalog);
        if (!decision.Allowed)
        {
            return AdminResult<User>.Forbidden(decision.Reason!);
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var before = Snapshot(target);
        var keepsFoundingRole = target.IsFoundingAdmin
            && newRole.IsAdmin
            && IsAccountBound(newRole.Family)
            && accounts.AgencyId == target.AgencyId
            && accounts.CorporateId == target.CorporateId;

        target.RoleKey = newRole.Key;
        target.AgencyId = accounts.AgencyId;
        target.CorporateId = accounts.CorporateId;
        target.IsFoundingAdmin = keepsFoundingRole
            || await BecomesFoundingAdminAsync(newRole, accounts.AgencyId, accounts.CorporateId, target.Id, cancellationToken);
        target.PermissionsVersion++;

        await PermissionChangeEffects.UserChangedAsync(db, target.TenantId, target.Id, cancellationToken);
        audit.Append(new AuditRecord("user.role-changed", "User", target.Id, before, Snapshot(target)));

        var conflict = await SaveAsync(cancellationToken);
        if (conflict is not null)
        {
            return AdminResult<User>.Conflict(conflict);
        }

        await transaction.CommitAsync(cancellationToken);
        return AdminResult<User>.Ok(target);
    }

    public async Task<AdminResult<User>> DeleteAsync(string id, CancellationToken cancellationToken)
    {
        var principal = principalContext.Current;

        var target = await support.FindVisibleAsync(principal, id, track: true, cancellationToken);
        if (target is null)
        {
            return AdminResult<User>.NotFound();
        }

        var actor = await support.ResolveActorAsync(principal, cancellationToken);
        if (actor is null)
        {
            return AdminResult<User>.Forbidden("Your role cannot manage users.");
        }

        var decision = management.StrategyFor(principal).Evaluate(
            actor,
            new ManagementRequest(ManagementOperation.Delete, ManagementSupport.ToManaged(target)),
            catalog);
        if (!decision.Allowed)
        {
            return AdminResult<User>.Forbidden(decision.Reason!);
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var before = Snapshot(target);
        target.DeletedAt = clock.GetUtcNow();
        target.IsFoundingAdmin = false;

        await PermissionChangeEffects.UserChangedAsync(db, target.TenantId, target.Id, cancellationToken);
        audit.Append(new AuditRecord("user.deleted", "User", target.Id, before, Snapshot(target)));

        var conflict = await SaveAsync(cancellationToken);
        if (conflict is not null)
        {
            return AdminResult<User>.Conflict(conflict);
        }

        await transaction.CommitAsync(cancellationToken);
        return AdminResult<User>.NoContent();
    }

    internal static object Snapshot(User user) => new
    {
        user.Handle,
        user.DisplayName,
        user.Kind,
        user.RoleKey,
        user.AgencyId,
        user.CorporateId,
        user.IsFoundingAdmin,
        Deleted = user.DeletedAt is not null,
    };

    private static bool IsAccountBound(RoleFamily family) => family is RoleFamily.Agency or RoleFamily.Corporate;

    /// <summary>
    /// Works out which account the user ends up in. Account-bound roles need an account: the caller's own when they are
    /// of that kind when the caller belongs to one, otherwise the user's current one, otherwise the request must name it. Other roles must not carry an account.
    /// </summary>
    private static (string? AgencyId, string? CorporateId, Dictionary<string, string[]>? Error) ResolveAccounts(
        RoleDefinition? callerRole, Principal caller, RoleDefinition role, string? requestedAgency, string? requestedCorporate, User? current)
    {
        string? agency = null;
        string? corporate = null;
        var errors = new Dictionary<string, string[]>();

        switch (role.Family)
        {
            case RoleFamily.Agency:
                agency = requestedAgency ?? (callerRole?.Family == RoleFamily.Agency ? caller.AgencyId : current?.AgencyId);
                if (string.IsNullOrWhiteSpace(agency) || !AccountPattern().IsMatch(agency))
                {
                    errors["agencyId"] = ["A valid agencyId is required for an agency role."];
                }

                if (requestedCorporate is not null)
                {
                    errors["corporateId"] = ["An agency role cannot belong to a corporate account."];
                }

                break;

            case RoleFamily.Corporate:
                corporate = requestedCorporate ?? (callerRole?.Family == RoleFamily.Corporate ? caller.CorporateId : current?.CorporateId);
                if (string.IsNullOrWhiteSpace(corporate) || !AccountPattern().IsMatch(corporate))
                {
                    errors["corporateId"] = ["A valid corporateId is required for a corporate role."];
                }

                if (requestedAgency is not null)
                {
                    errors["agencyId"] = ["A corporate role cannot belong to an agency."];
                }

                break;

            default:
                if (requestedAgency is not null)
                {
                    errors["agencyId"] = ["This role does not belong to an agency."];
                }

                if (requestedCorporate is not null)
                {
                    errors["corporateId"] = ["This role does not belong to a corporate account."];
                }

                break;
        }

        return (agency, corporate, errors.Count > 0 ? errors : null);
    }

    /// <summary>The first admin of an agency or corporate account becomes its founding admin.</summary>
    private async Task<bool> BecomesFoundingAdminAsync(
        RoleDefinition role, string? agencyId, string? corporateId, string? excludedUserId, CancellationToken cancellationToken)
    {
        if (!role.IsAdmin || !IsAccountBound(role.Family))
        {
            return false;
        }

        var query = db.Users.Where(u => u.IsFoundingAdmin && u.Id != excludedUserId);
        var exists = role.Family == RoleFamily.Agency
            ? await query.AnyAsync(u => u.AgencyId == agencyId, cancellationToken)
            : await query.AnyAsync(u => u.CorporateId == corporateId, cancellationToken);
        return !exists;
    }

    /// <summary>Saves the unit of work. A unique violation (handle taken, founding admin race) is reported as a conflict message.</summary>
    private async Task<string?> SaveAsync(CancellationToken cancellationToken)
    {
        try
        {
            await db.SaveChangesAsync(cancellationToken);
            return null;
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            return "A conflicting user exists: the handle is in use or the account already has a founding admin.";
        }
    }

    internal static bool IsUniqueViolation(DbUpdateException exception) => exception.InnerException switch
    {
        PostgresException postgres => postgres.SqlState == PostgresErrorCodes.UniqueViolation,
        SqliteException sqlite => sqlite.SqliteErrorCode == 19 && sqlite.SqliteExtendedErrorCode is 2067 or 1555,
        _ => false,
    };
}
