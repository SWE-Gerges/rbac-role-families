using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

[Trait("Category", "Integration")]
public class StartupLogTests
{
    [Fact]
    public async Task A_fresh_sqlite_start_and_a_few_requests_log_nothing_at_error_level_or_from_data_protection()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = ApiFactory.With(new ApiFactoryOptions { Logs = logs });
        using var client = await factory.ClientForAsync(SeedIds.AgencyStaffA);

        (await client.GetAsync("/api/v1/bookings")).EnsureSuccessStatusCode();
        (await client.GetAsync("/health/ready")).EnsureSuccessStatusCode();

        LogAssertions.AssertQuiet(logs);
    }

    [Fact]
    public void The_data_protection_key_ring_warm_up_is_not_registered()
    {
        using var factory = new ApiFactory();

        var hostedServices = factory.Services.GetServices<IHostedService>().Select(s => s.GetType().FullName).ToArray();

        hostedServices.ShouldNotContain("Microsoft.AspNetCore.DataProtection.Internal.DataProtectionHostedService");
        hostedServices.ShouldContain(name => name!.EndsWith("RbacStartupValidator", StringComparison.Ordinal));
    }
}
