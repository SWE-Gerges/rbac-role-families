using System.Text.Json;

namespace Rbac.Tests.Matrix;

public sealed record CreationScenario(
    string Caller,
    string CallerRole,
    bool Founder,
    string TargetRole,
    string Account,
    string? AgencyId,
    string? CorporateId,
    int ExpectedStatus);

public sealed record CreationMatrixFile(string Description, IReadOnlyList<CreationScenario> Rows)
{
    public static CreationMatrixFile Load()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Matrix", "creation-matrix.json");
        using var stream = File.OpenRead(path);
        return JsonSerializer.Deserialize<CreationMatrixFile>(stream, new JsonSerializerOptions(JsonSerializerDefaults.Web))
            ?? throw new InvalidOperationException("creation-matrix.json is empty.");
    }
}
