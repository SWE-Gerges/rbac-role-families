using System.Text.Json;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Rbac.Demo.Health;

/// <summary>Writes the overall status and each check's status. Exception details are never written.</summary>
internal static class HealthResponseWriter
{
    public static Task WriteAsync(HttpContext context, HealthReport report)
    {
        context.Response.ContentType = "application/json";
        var payload = new
        {
            status = report.Status.ToString(),
            checks = report.Entries.ToDictionary(e => e.Key, e => e.Value.Status.ToString()),
        };
        return context.Response.WriteAsync(JsonSerializer.Serialize(payload), context.RequestAborted);
    }
}
