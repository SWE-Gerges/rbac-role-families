using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;
using Rbac.Persistence;
using Rbac.Persistence.Seeding;
using Rbac.Tests.Support;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Matrix;

/// <summary>
/// The committed matrix (access-matrix.json) is the expected behaviour per role and scenario. These tests check it
/// is complete and that the strategies, run against the seeded database, reproduce every expected id list.
/// </summary>
public class AccessMatrixTests
{
    private static readonly AccessMatrixFile Matrix = AccessMatrixFile.Load();

    [Fact]
    public void Every_defined_role_has_list_rows_and_action_rows()
    {
        foreach (var role in DefaultRoleCatalog.Create().Roles)
        {
            Matrix.List.ShouldContain(r => r.Role == role.Key, $"no list row for role '{role.Key}'");
            Matrix.Actions.ShouldContain(r => r.Role == role.Key, $"no action row for role '{role.Key}'");
        }

        Matrix.List.ShouldContain(r => r.Role == "customer");
        Matrix.Actions.ShouldContain(r => r.Role == "customer");
    }

    [Fact]
    public void Every_seeded_user_appears_in_the_matrix()
    {
        foreach (var user in DemoSeedData.Users)
        {
            Matrix.List.ShouldContain(r => r.User == user.Id, $"no list row for user '{user.Id}'");
            Matrix.Actions.ShouldContain(r => r.User == user.Id, $"no action row for user '{user.Id}'");
        }
    }

    [Fact]
    public void Every_role_in_the_matrix_is_a_defined_role_or_a_customer()
    {
        var known = DefaultRoleCatalog.Create().Roles.Select(r => r.Key).Append("customer").ToHashSet();

        Matrix.List.Select(r => r.Role).Concat(Matrix.Actions.Select(r => r.Role)).ShouldAllBe(role => known.Contains(role));
    }

    [Fact]
    public void The_matrix_covers_every_outcome_the_api_documents_for_reads_cancels_and_permission_edits()
    {
        var statuses = Matrix.Actions.Select(a => a.ExpectedStatus).Distinct().Order().ToArray();

        statuses.ShouldBe([200, 400, 403, 404, 409, 428]);
    }

    [Fact]
    public async Task The_strategies_reproduce_every_expected_booking_id_list()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var fixture = TestServices.Resolver();

        foreach (var row in Matrix.List)
        {
            var user = SeedPrincipals.User(row.User);
            var principal = SeedPrincipals.From(user);
            await using var db = database.CreateContext(user.TenantId);
            var permissions = await new DbPermissionStore(db).GetEffectivePermissionsAsync(principal, TestContext.Current.CancellationToken);

            if (row.ExpectedStatus == 403)
            {
                permissions.Has(Permissions.BookingsRead).ShouldBeFalse($"{row.User}: expected 403 means no bookings.read");
                continue;
            }

            permissions.Has(Permissions.BookingsRead).ShouldBeTrue($"{row.User}: expected 200 means bookings.read");

            var strategy = fixture.Resolver.StrategyFor(principal);
            var query = db.Bookings.AsNoTracking().Where(strategy.Scope(principal, permissions));
            query = ApplyQuery(query, row.Query, principal);

            var actual = (await query.Select(b => b.Id).ToListAsync(TestContext.Current.CancellationToken)).Order(StringComparer.Ordinal).ToArray();

            actual.ShouldBe(row.BookingIds!.ToArray(), $"{row.User} / {row.Scenario}");
        }
    }

    [Fact]
    public async Task The_user_scopes_reproduce_every_expected_user_id_list()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var fixture = TestServices.Resolver();

        foreach (var row in Matrix.Users)
        {
            var user = SeedPrincipals.User(row.User);
            var principal = SeedPrincipals.From(user);
            await using var db = database.CreateContext(user.TenantId);
            var permissions = await new DbPermissionStore(db).GetEffectivePermissionsAsync(principal, TestContext.Current.CancellationToken);

            if (row.ExpectedStatus == 403)
            {
                permissions.Has(Permissions.UsersRead).ShouldBeFalse($"{row.User}: expected 403 means no users.read");
                continue;
            }

            permissions.Has(Permissions.UsersRead).ShouldBeTrue(row.User);
            var actual = (await db.Users.AsNoTracking().Where(fixture.Users.Resolve(principal, permissions)).Select(u => u.Id).ToListAsync(TestContext.Current.CancellationToken))
                .Order(StringComparer.Ordinal)
                .ToArray();

            actual.ShouldBe(row.UserIds!.ToArray(), row.User);
        }
    }

    private static IQueryable<Booking> ApplyQuery(IQueryable<Booking> query, string queryString, Principal principal)
    {
        switch (queryString)
        {
            case "":
                return query;
            case "status=Refunded":
                return query.Where(b => b.Status == BookingStatus.Refunded);
            case "mine=true":
                Expression<Func<Booking, bool>> mine = b => b.OwnerUserId == principal.UserId;
                return query.Where(mine);
            default:
                throw new InvalidOperationException($"Unknown matrix query '{queryString}'.");
        }
    }
}
