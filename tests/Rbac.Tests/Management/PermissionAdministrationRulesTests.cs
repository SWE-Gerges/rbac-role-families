using Rbac.Abstractions;
using Rbac.Core.Catalog;
using Rbac.Core.Management;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Management;

public class PermissionAdministrationRulesTests
{
    private static IReadOnlySet<string> Set(params string[] values) => values.ToHashSet(StringComparer.Ordinal);

    private static IReadOnlyDictionary<string, bool> Overrides(params (string Permission, bool Grant)[] values) =>
        values.ToDictionary(v => v.Permission, v => v.Grant, StringComparer.Ordinal);

    [Fact]
    public void A_caller_can_touch_only_what_they_hold()
    {
        var held = PermissionSet.Create(Permissions.BookingsRead, Permissions.BookingsCancel);

        GrantCeiling.Check(held, [Permissions.BookingsRead, Permissions.BookingsCancel]).ShouldBeEmpty();

        var violations = GrantCeiling.Check(held, [Permissions.BookingsRead, Permissions.ReportsView]);
        violations.Select(v => v.Permission).ShouldBe([Permissions.ReportsView]);
    }

    [Fact]
    public void Revoking_is_held_to_the_same_ceiling_as_granting_because_both_are_just_touches()
    {
        GrantCeiling.Check(PermissionSet.Empty, [Permissions.BookingsCancel]).ShouldNotBeEmpty();
    }

    [Fact]
    public void A_reserved_permission_is_untouchable_even_for_a_caller_who_holds_it()
    {
        var held = PermissionSet.Create(Permissions.RolesManagePermissions);

        GrantCeiling.Check(held, [Permissions.RolesManagePermissions]).ShouldHaveSingleItem().Permission.ShouldBe(Permissions.RolesManagePermissions);
    }

    [Fact]
    public void The_reserved_permission_is_held_by_system_family_roles_only()
    {
        foreach (var role in DefaultRoleCatalog.Create().Roles.Where(r => r.DefaultPermissions.Overlaps(Permissions.Reserved)))
        {
            role.Family.ShouldBe(RoleFamily.System, role.Key);
        }
    }

    [Fact]
    public void Granting_something_the_role_lacks_stores_a_grant_and_granting_something_it_has_stores_nothing()
    {
        var defaults = Set(Permissions.BookingsRead);

        var granted = PermissionDiffer.Apply(defaults, Overrides(), new([Permissions.ReportsView, Permissions.BookingsRead], [], []));

        granted.Overrides.ShouldBe(new Dictionary<string, bool> { [Permissions.ReportsView] = true });
        granted.Changed.ShouldBe([Permissions.ReportsView]);
    }

    [Fact]
    public void Revoking_a_role_default_stores_a_revoke_and_revoking_something_not_held_stores_nothing()
    {
        var defaults = Set(Permissions.BookingsRead);

        var revoked = PermissionDiffer.Apply(defaults, Overrides(), new([], [Permissions.BookingsRead, Permissions.ReportsView], []));

        revoked.Overrides.ShouldBe(new Dictionary<string, bool> { [Permissions.BookingsRead] = false });
        revoked.Changed.ShouldBe([Permissions.BookingsRead]);
    }

    [Fact]
    public void Revoking_a_per_user_grant_removes_it_and_granting_a_revoked_default_removes_the_revoke()
    {
        var defaults = Set(Permissions.BookingsRead);
        var current = Overrides((Permissions.ReportsView, true), (Permissions.BookingsRead, false));

        var result = PermissionDiffer.Apply(defaults, current, new([Permissions.BookingsRead], [Permissions.ReportsView], []));

        result.Overrides.ShouldBeEmpty();
        result.Changed.ShouldBe([Permissions.BookingsRead, Permissions.ReportsView], ignoreOrder: true);
    }

    [Fact]
    public void Reset_returns_a_permission_to_the_role_default()
    {
        var defaults = Set(Permissions.BookingsRead);
        var current = Overrides((Permissions.ReportsView, true), (Permissions.BookingsRead, false));

        var result = PermissionDiffer.Apply(defaults, current, new([], [], [Permissions.ReportsView, Permissions.BookingsRead]));

        result.Overrides.ShouldBeEmpty();
        PermissionDiffer.Effective(defaults, result.Overrides).ShouldBe([Permissions.BookingsRead]);
    }

    [Fact]
    public void An_empty_diff_and_a_repeated_diff_change_nothing()
    {
        var defaults = Set(Permissions.BookingsRead);
        var diff = new PermissionDiffRequest([Permissions.ReportsView], [Permissions.BookingsRead], []);

        PermissionDiffer.Apply(defaults, Overrides(), PermissionDiffRequest.Empty).HasChanges.ShouldBeFalse();

        var first = PermissionDiffer.Apply(defaults, Overrides(), diff);
        var second = PermissionDiffer.Apply(defaults, first.Overrides, diff);

        first.HasChanges.ShouldBeTrue();
        second.HasChanges.ShouldBeFalse();
        second.Overrides.ShouldBe(first.Overrides);
    }

    [Fact]
    public void A_permission_in_two_lists_is_reported()
    {
        PermissionDiffer.Duplicates(new([Permissions.BookingsRead], [Permissions.BookingsRead, Permissions.ReportsView], [Permissions.ReportsView]))
            .ShouldBe([Permissions.BookingsRead, Permissions.ReportsView]);
        PermissionDiffer.Duplicates(new([Permissions.BookingsRead], [Permissions.ReportsView], [])).ShouldBeEmpty();
    }

    [Fact]
    public void Whatever_the_diff_the_effective_set_is_what_the_diff_asked_for_and_untouched_permissions_stay_put()
    {
        string[] universe = [.. Permissions.All.Take(8)];
        var random = new Random(20260101);

        for (var round = 0; round < 500; round++)
        {
            var defaults = universe.Where(_ => random.Next(2) == 0).ToHashSet(StringComparer.Ordinal);
            var current = universe.Where(_ => random.Next(3) == 0).ToDictionary(p => p, _ => random.Next(2) == 0, StringComparer.Ordinal);
            // Existing overrides are minimal by construction, as the differ keeps them.
            current = current.Where(o => o.Value != defaults.Contains(o.Key)).ToDictionary(o => o.Key, o => o.Value, StringComparer.Ordinal);

            var shuffled = universe.OrderBy(_ => random.Next()).ToArray();
            var diff = new PermissionDiffRequest(shuffled[..2], shuffled[2..4], shuffled[4..5]);
            var before = PermissionDiffer.Effective(defaults, current);

            var result = PermissionDiffer.Apply(defaults, current, diff);
            var after = PermissionDiffer.Effective(defaults, result.Overrides).ToHashSet(StringComparer.Ordinal);

            diff.Grant.ShouldAllBe(p => after.Contains(p));
            diff.Revoke.ShouldAllBe(p => !after.Contains(p));
            diff.Reset.ShouldAllBe(p => after.Contains(p) == defaults.Contains(p));
            foreach (var untouched in universe.Except(diff.Touched))
            {
                after.Contains(untouched).ShouldBe(before.Contains(untouched), $"round {round}: {untouched}");
            }

            result.Overrides.ShouldAllBe(o => o.Value != defaults.Contains(o.Key), "stored overrides stay minimal");
            PermissionDiffer.Apply(defaults, result.Overrides, diff).HasChanges.ShouldBeFalse("a diff is idempotent");
        }
    }
}
