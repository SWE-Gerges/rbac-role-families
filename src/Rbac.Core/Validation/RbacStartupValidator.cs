using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Rbac.Abstractions;
using Rbac.Core.Registry;

namespace Rbac.Core.Validation;

/// <summary>Fails the host at startup when the RBAC configuration is inconsistent.</summary>
public sealed class RbacStartupValidator(
    IRoleCatalog catalog,
    IEnumerable<IStrategyRegistry> registries,
    ILogger<RbacStartupValidator> logger) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var problems = RbacConfigurationValidator.Validate(catalog, registries);
        if (problems.Count == 0)
        {
            return Task.CompletedTask;
        }

        foreach (var problem in problems)
        {
            logger.LogCritical("RBAC configuration problem: {Problem}", problem);
        }

        throw new RbacConfigurationException(problems);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
