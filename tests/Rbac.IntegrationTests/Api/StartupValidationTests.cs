using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;
using Rbac.Core.Registry;
using Rbac.Core.Scopes;
using Rbac.Core.Validation;
using Rbac.IntegrationTests.Support;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

/// <summary>Each misconfiguration must stop the host before it serves a single request.</summary>
[Trait("Category", "Integration")]
public class StartupValidationTests
{
    private static ApiFactory FactoryWith(Action<IServiceCollection> configure, IReadOnlyDictionary<string, string?>? settings = null) =>
        ApiFactory.With(new ApiFactoryOptions { ConfigureServices = configure, Settings = settings ?? new Dictionary<string, string?>() });

    private static StrategyRegistryBuilder<Booking> AllFamilies() => StrategyRegistry<Booking>.Create()
        .ForFamily(RoleFamily.System, new SystemScope())
        .ForFamily(RoleFamily.Finance, new FinanceScope())
        .ForFamily(RoleFamily.Internal, new InternalScope())
        .ForFamily(RoleFamily.Corporate, new CorporateScope())
        .ForFamily(RoleFamily.Agency, new AgencyScope())
        .ForFamily(RoleFamily.Viewer, new ViewerScope());

    private static void ReplaceCatalog(IServiceCollection services, IRoleCatalog catalog)
    {
        services.RemoveAll<IRoleCatalog>();
        services.AddSingleton(catalog);
    }

    private static void ReplaceRegistry(IServiceCollection services, StrategyRegistry<Booking> registry)
    {
        services.RemoveAll<StrategyRegistry<Booking>>();
        services.RemoveAll<IStrategyRegistry>();
        services.AddSingleton(registry);
        services.AddSingleton<IStrategyRegistry>(registry);
    }

    private static async Task<RbacConfigurationException> StartAndCaptureAsync(ApiFactory factory)
    {
        using (factory)
        {
            var exception = await Should.ThrowAsync<Exception>(() => Task.Run(() => factory.CreateClient().Dispose()));
            for (Exception? current = exception; current is not null; current = current.InnerException)
            {
                if (current is RbacConfigurationException configuration)
                {
                    return configuration;
                }
            }

            throw new InvalidOperationException("The host failed, but not with an RbacConfigurationException: " + exception);
        }
    }

    [Fact]
    public async Task A_role_without_a_family_fails_the_host()
    {
        var catalog = RoleCatalog.Create().Role("orphan", default).Build();

        var failure = await StartAndCaptureAsync(FactoryWith(s => ReplaceCatalog(s, catalog)));

        failure.Problems.ShouldContain(p => p.Contains("'orphan'") && p.Contains("no valid role family"));
    }

    [Fact]
    public async Task A_family_without_a_strategy_fails_the_host()
    {
        var registry = StrategyRegistry<Booking>.Create().ForFamily(RoleFamily.System, new SystemScope()).Build();

        var failure = await StartAndCaptureAsync(FactoryWith(s => ReplaceRegistry(s, registry)));

        failure.Problems.ShouldContain(p => p.Contains("'Agency'") && p.Contains("no strategy"));
    }

    [Fact]
    public async Task A_family_with_two_strategies_fails_the_host()
    {
        var registry = AllFamilies().ForFamily(RoleFamily.Agency, new InternalScope()).Build();

        var failure = await StartAndCaptureAsync(FactoryWith(s => ReplaceRegistry(s, registry)));

        failure.Problems.ShouldContain(p => p.Contains("'Agency'") && p.Contains("exactly one"));
    }

    [Fact]
    public async Task A_strategy_for_an_undefined_family_fails_the_host()
    {
        var registry = AllFamilies().ForFamily((RoleFamily)77, new SystemScope()).Build();

        var failure = await StartAndCaptureAsync(FactoryWith(s => ReplaceRegistry(s, registry)));

        failure.Problems.ShouldContain(p => p.Contains("undefined family '77'"));
    }

    [Fact]
    public async Task Two_roles_with_the_same_key_fail_the_host()
    {
        var catalog = DefaultRoleCatalog.Create();
        var duplicated = RoleCatalog.FromDefinitions([.. catalog.Roles, catalog.Roles[0]]);

        var failure = await StartAndCaptureAsync(FactoryWith(s => ReplaceCatalog(s, duplicated)));

        failure.Problems.ShouldContain(p => p.Contains("'system-admin'") && p.Contains("2 times"));
    }

    [Fact]
    public async Task A_creatable_role_that_does_not_exist_fails_the_host()
    {
        var catalog = RoleCatalog.Create()
            .Role(RoleKeys.SystemAdmin, RoleFamily.System, r => r.CanCreate("ghost"))
            .Build();

        var failure = await StartAndCaptureAsync(FactoryWith(s => ReplaceCatalog(s, catalog)));

        failure.Problems.ShouldContain(p => p.Contains("'ghost'"));
    }

    [Fact]
    public async Task A_signing_key_shorter_than_32_bytes_fails_the_host()
    {
        using var factory = ApiFactory.With(new ApiFactoryOptions
        {
            Settings = new Dictionary<string, string?> { ["Demo:Jwt:SigningKey"] = "too-short" },
        });

        var exception = await Should.ThrowAsync<Exception>(() => Task.Run(() => factory.CreateClient().Dispose()));

        Flatten(exception).ShouldContain(e => e is OptionsValidationException && e.Message.Contains("SigningKey"));
    }

    [Fact]
    public async Task A_missing_database_connection_string_fails_the_host()
    {
        using var factory = ApiFactory.With(new ApiFactoryOptions
        {
            Settings = new Dictionary<string, string?> { ["Persistence:ConnectionString"] = "" },
        });

        var exception = await Should.ThrowAsync<Exception>(() => Task.Run(() => factory.CreateClient().Dispose()));

        Flatten(exception).ShouldContain(e => e is OptionsValidationException && e.Message.Contains("ConnectionString"));
    }

    [Fact]
    public async Task A_valid_configuration_starts()
    {
        using var factory = new ApiFactory();

        using var client = factory.CreateClient();

        (await client.GetAsync("/health/live")).IsSuccessStatusCode.ShouldBeTrue();
    }

    private static IEnumerable<Exception> Flatten(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            yield return current;
        }
    }
}
