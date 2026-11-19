using Microsoft.Extensions.Logging;
using Shouldly;

namespace Rbac.IntegrationTests.Support;

public static class LogAssertions
{
    /// <summary>A healthy start logs nothing at error level and nothing from data protection above information.</summary>
    public static void AssertQuiet(CapturingLoggerProvider logs)
    {
        var problems = logs.Entries
            .Where(e => e.Level >= LogLevel.Error
                        || (e.Level >= LogLevel.Warning && e.Category.Contains("DataProtection", StringComparison.Ordinal)))
            .Select(e => $"{e.Level} {e.Category}: {e.Message}")
            .ToArray();

        problems.ShouldBeEmpty(string.Join(Environment.NewLine, problems));
        logs.Entries.ShouldContain(e => e.Message.Contains("Database ready", StringComparison.Ordinal), "the capture must actually see startup logs");
    }
}
