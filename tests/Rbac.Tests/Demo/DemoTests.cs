using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.JsonWebTokens;
using Rbac.Demo;
using Rbac.Persistence;
using Rbac.Tests.Support;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Demo;

public partial class DemoTests
{
    [GeneratedRegex(@"\.Bookings\b")]
    private static partial Regex BookingsAccess();

    [Fact]
    public void Issued_tokens_expire_after_the_configured_lifetime_on_the_injected_clock()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 3, 1, 12, 0, 0, TimeSpan.Zero));
        var options = Options.Create(new DemoOptions
        {
            Jwt = { Issuer = "issuer", Audience = "audience", SigningKey = new string('k', 32), TokenLifetimeMinutes = 15 },
        });

        var issued = new DevTokenIssuer(options, clock).Issue([new System.Security.Claims.Claim("sub", "u1")]);

        issued.ExpiresAt.ShouldBe(new DateTimeOffset(2026, 3, 1, 12, 15, 0, TimeSpan.Zero));
        var token = new JsonWebTokenHandler().ReadJsonWebToken(issued.AccessToken);
        token.ValidTo.ShouldBe(issued.ExpiresAt.UtcDateTime);
        token.ValidFrom.ShouldBe(clock.GetUtcNow().UtcDateTime);
        token.Issuer.ShouldBe("issuer");
        token.Alg.ShouldBe("HS256");
    }

    [Fact]
    public void Demo_options_require_a_signing_key_of_at_least_32_bytes()
    {
        var validator = new DemoOptionsValidator();
        var options = new DemoOptions { Jwt = { Issuer = "i", Audience = "a", SigningKey = new string('k', 31) } };

        var result = validator.Validate(null, options);

        result.Failed.ShouldBeTrue();
        result.Failures.ShouldContain(f => f.Contains("SigningKey"));

        options.Jwt.SigningKey = new string('k', 32);
        validator.Validate(null, options).Succeeded.ShouldBeTrue();
    }

    [Fact]
    public void Demo_options_reject_a_missing_issuer_audience_and_a_silly_lifetime()
    {
        var result = new DemoOptionsValidator().Validate(null, new DemoOptions { Jwt = { SigningKey = new string('k', 40), TokenLifetimeMinutes = 0 } });

        result.Failures.ShouldNotBeNull();
        result.Failures.Count().ShouldBe(3);
    }

    [Fact]
    public void Endpoints_read_bookings_only_through_the_scoped_query()
    {
        var demoSources = Directory.EnumerateFiles(RepoPaths.FromRoot("src", "Rbac.Demo"), "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                        && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal));

        var offenders = new List<string>();
        foreach (var file in demoSources)
        {
            foreach (var line in File.ReadLines(file).Select((text, index) => (text, index)))
            {
                if (!line.text.TrimStart().StartsWith("using ", StringComparison.Ordinal)
                    && BookingsAccess().IsMatch(line.text)
                    && !line.text.Contains("db.Bookings.Add(", StringComparison.Ordinal))
                {
                    offenders.Add($"{Path.GetFileName(file)}:{line.index + 1}: {line.text.Trim()}");
                }
            }
        }

        offenders.ShouldBeEmpty("only IScopedQuery<Booking>.ScopedFor may read bookings; the one allowed DbSet use is Add");
    }

    [Fact]
    public void The_npgsql_model_has_no_pending_changes_compared_with_the_committed_migrations()
    {
        var options = new DbContextOptionsBuilder<RbacDbContext>()
            .UseNpgsql("Host=localhost;Database=never_connected;Username=u;Password=not-a-secret")
            .Options;
        using var db = new RbacDbContext(options, FixedTenantContext.None);

        db.Database.HasPendingModelChanges().ShouldBeFalse("add a migration after changing the model");
        db.Database.GetMigrations().ShouldNotBeEmpty();
    }
}
