using System.Linq.Expressions;
using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;
using Rbac.Core.Scopes;
using Rbac.Tests.Support;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Registry;

public class NarrowedScopeTests
{
    private static readonly (IAccessScopeStrategy<Booking> Strategy, Principal Principal, PermissionSet Permissions)[] Cases =
    [
        (new SystemScope(), Principals.SystemAdmin(), PermissionSet.Empty),
        (new InternalScope(), Principals.InternalStaff(), PermissionSet.Empty),
        (new AgencyScope(), Principals.AgencyAdmin(), PermissionSet.Empty),
        (new AgencyScope(), Principals.AgencyStaff(), PermissionSet.Create(Permissions.BookingsViewAllAgency)),
        (new CorporateScope(), Principals.CorporateAdmin(), PermissionSet.Empty),
        (new FinanceScope(), Principals.Finance(), PermissionSet.Create(Permissions.ReportsView)),
        (new FinanceScope(), Principals.Finance(), PermissionSet.Empty),
        (new CustomerScope(), Principals.Customer(), PermissionSet.Empty),
        (new ViewerScope(), Principals.Viewer(), PermissionSet.Empty),
    ];

    [Fact]
    public void Narrowing_never_adds_rows_and_equals_the_intersection_for_randomly_generated_predicates()
    {
        var random = new Random(424242);
        var checkedPredicates = 0;

        for (var i = 0; i < 120; i++)
        {
            var extra = RandomPredicate(random, depth: 3);

            foreach (var (strategy, principal, permissions) in Cases)
            {
                var inner = ScopeDataset.Visible(ScopeDataset.Query, strategy, principal, permissions);
                var narrowed = ScopeDataset.Visible(ScopeDataset.Query, strategy.Narrow(extra), principal, permissions);
                var matching = ScopeDataset.Query.Where(extra).Select(b => b.Id).ToHashSet();

                narrowed.ShouldBeSubsetOf(inner, strategy.Name);
                narrowed.ShouldBe(inner.Where(matching.Contains).ToArray(), strategy.Name);
                checkedPredicates++;
            }
        }

        checkedPredicates.ShouldBe(120 * Cases.Length);
    }

    [Fact]
    public void A_narrowing_that_matches_everything_changes_nothing()
    {
        foreach (var (strategy, principal, permissions) in Cases)
        {
            var inner = ScopeDataset.Visible(ScopeDataset.Query, strategy, principal, permissions);
            var narrowed = ScopeDataset.Visible(ScopeDataset.Query, strategy.Narrow(_ => true), principal, permissions);

            narrowed.ShouldBe(inner);
        }
    }

    [Fact]
    public void A_narrowing_that_matches_nothing_hides_everything()
    {
        foreach (var (strategy, principal, permissions) in Cases)
        {
            ScopeDataset.Visible(ScopeDataset.Query, strategy.Narrow(_ => false), principal, permissions).ShouldBeEmpty();
        }
    }

    [Fact]
    public void An_extra_predicate_cannot_widen_a_scope_even_if_it_matches_other_tenants()
    {
        var narrowed = new SystemScope().Narrow(b => b.TenantId == ScopeDataset.TenantB || b.TenantId == ScopeDataset.TenantA);

        ScopeDataset.Visible(ScopeDataset.Query, narrowed, Principals.SystemAdmin(), PermissionSet.Empty)
            .ShouldAllBe(id => !id.StartsWith("b2", StringComparison.Ordinal));
    }

    [Fact]
    public void Narrowing_keeps_the_name_of_the_inner_strategy()
    {
        new AgencyScope().Narrow(_ => true).Name.ShouldBe(nameof(AgencyScope));
    }

    private static Expression<Func<Booking, bool>> RandomPredicate(Random random, int depth)
    {
        if (depth == 0 || random.Next(3) == 0)
        {
            return Leaf(random);
        }

        var left = RandomPredicate(random, depth - 1);
        var right = RandomPredicate(random, depth - 1);
        var parameter = Expression.Parameter(typeof(Booking), "b");
        Expression body = random.Next(3) switch
        {
            0 => Expression.AndAlso(Replace(left, parameter), Replace(right, parameter)),
            1 => Expression.OrElse(Replace(left, parameter), Replace(right, parameter)),
            _ => Expression.Not(Replace(left, parameter)),
        };
        return Expression.Lambda<Func<Booking, bool>>(body, parameter);
    }

    private static Expression<Func<Booking, bool>> Leaf(Random random)
    {
        var statuses = Enum.GetValues<BookingStatus>();
        var types = Enum.GetValues<BookingType>();
        var status = statuses[random.Next(statuses.Length)];
        var type = types[random.Next(types.Length)];
        var owners = ScopeDataset.Bookings.Select(b => b.OwnerUserId).Distinct().ToArray();
        var owner = owners[random.Next(owners.Length)];

        return random.Next(5) switch
        {
            0 => b => b.Status == status,
            1 => b => b.Type == type,
            2 => b => b.OwnerUserId == owner,
            3 => b => b.IsGuestBooking,
            _ => b => b.AgencyId != null,
        };
    }

    private static Expression Replace(LambdaExpression lambda, ParameterExpression parameter) =>
        new Rebinder(lambda.Parameters[0], parameter).Visit(lambda.Body);

    private sealed class Rebinder(ParameterExpression from, ParameterExpression to) : ExpressionVisitor
    {
        protected override Expression VisitParameter(ParameterExpression node) => node == from ? to : base.VisitParameter(node);
    }
}
