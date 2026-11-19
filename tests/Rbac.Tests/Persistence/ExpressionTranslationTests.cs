using Microsoft.EntityFrameworkCore;
using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Scopes;
using Rbac.Persistence;
using Rbac.Persistence.Seeding;
using Rbac.Tests.Support;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Persistence;

public class ExpressionTranslationTests
{
    [Fact]
    public async Task Every_strategy_translates_to_sql_for_every_seeded_caller_and_matches_in_memory_evaluation()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var fixture = TestServices.Resolver();

        List<Booking> all;
        await using (var unfiltered = database.CreateContext(tenantId: null))
        {
            all = await unfiltered.Bookings.IgnoreQueryFilters().AsNoTracking().ToListAsync(TestContext.Current.CancellationToken);
        }

        var strategiesSeen = new HashSet<string>();

        foreach (var user in DemoSeedData.Users)
        {
            await using var db = database.CreateContext(user.TenantId);
            var principal = SeedPrincipals.From(user);
            var permissions = await new DbPermissionStore(db).GetEffectivePermissionsAsync(principal, TestContext.Current.CancellationToken);

            var strategy = fixture.Resolver.StrategyFor(principal);
            strategiesSeen.Add(strategy.Name);
            var expression = strategy.Scope(principal, permissions);

            var query = db.Bookings.Where(expression);
            query.ToQueryString().ShouldContain("TenantId", customMessage: $"{user.Id}: the tenant must be constrained in SQL");

            var actual = await query.Select(b => b.Id).ToListAsync(TestContext.Current.CancellationToken);
            var expected = all.Where(expression.Compile()).Select(b => b.Id).ToList();

            actual.ShouldBe(expected, ignoreOrder: true, customMessage: user.Id);
        }

        database.Warnings.ShouldBeEmpty("EF must not warn about untranslatable or client evaluated predicates");
        strategiesSeen.ShouldBe(
            [nameof(SystemScope), nameof(FinanceScope), nameof(InternalScope), nameof(CorporateScope), nameof(AgencyScope), nameof(ViewerScope), nameof(CustomerScope)],
            ignoreOrder: true);
    }

    [Fact]
    public async Task The_fail_closed_strategies_also_translate()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(SeedIds.TenantA);
        var fixture = TestServices.Resolver();

        Principal[] principals =
        [
            Principal.Anonymous,
            Principal.ForStaff("ghost", SeedIds.TenantA, "not-a-role"),
            Principal.ForStaff("a-agency-staff", SeedIds.TenantA, "agency-staff"),
            Principal.ForStaff("a-corporate-admin", SeedIds.TenantA, "corporate-admin"),
        ];

        foreach (var principal in principals)
        {
            var expression = fixture.Resolver.Resolve(principal, PermissionSet.Create("bookings.view-all-agency", "bookings.view-all-corporate"));

            (await db.Bookings.Where(expression).CountAsync(TestContext.Current.CancellationToken))
                .ShouldBe(0, $"{principal.UserId} has no usable scope");
        }

        database.Warnings.ShouldBeEmpty();
    }

    [Fact]
    public async Task Narrowed_scopes_translate_and_stay_inside_the_inner_scope()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(SeedIds.TenantA);
        var fixture = TestServices.Resolver();
        var user = SeedPrincipals.User(SeedIds.AgencyAdminA);
        var principal = SeedPrincipals.From(user);
        var permissions = await new DbPermissionStore(db).GetEffectivePermissionsAsync(principal, TestContext.Current.CancellationToken);

        var strategy = fixture.Resolver.StrategyFor(principal);
        var inner = await db.Bookings.Where(strategy.Scope(principal, permissions)).Select(b => b.Id).ToListAsync(TestContext.Current.CancellationToken);
        var narrowed = await db.Bookings
            .Where(strategy.Narrow(b => b.OwnerUserId == principal.UserId && b.Status != BookingStatus.Cancelled).Scope(principal, permissions))
            .Select(b => b.Id)
            .ToListAsync(TestContext.Current.CancellationToken);

        narrowed.ShouldNotBeEmpty();
        narrowed.ShouldBeSubsetOf(inner);
        narrowed.Count.ShouldBeLessThan(inner.Count);
        database.Warnings.ShouldBeEmpty();
    }

    [Fact]
    public async Task The_harness_really_detects_client_evaluation()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using var db = database.CreateContext(SeedIds.TenantA);

        await Should.ThrowAsync<InvalidOperationException>(async () =>
            await db.Bookings.Where(b => NotTranslatable(b.Id)).ToListAsync(TestContext.Current.CancellationToken));
    }

    private static bool NotTranslatable(string id) => id.Length > 3 && id.GetHashCode(StringComparison.Ordinal) != 0;
}
