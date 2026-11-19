using System.Text.Json;
using System.Text.Json.Serialization;

namespace Rbac.Tests.Matrix;

public sealed record ListScenario(
    string User,
    string Role,
    string Scenario,
    string Query,
    int ExpectedStatus,
    IReadOnlyList<string>? BookingIds);

public sealed record UserListScenario(
    string User,
    string Role,
    string Scenario,
    int ExpectedStatus,
    IReadOnlyList<string>? UserIds);

public sealed record ActionScenario(
    string User,
    string Role,
    string Scenario,
    string Method,
    string Path,
    int ExpectedStatus,
    JsonElement? Body);

public sealed record AccessMatrixFile(
    string Description,
    IReadOnlyList<ListScenario> List,
    IReadOnlyList<UserListScenario> Users,
    IReadOnlyList<ActionScenario> Actions)
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
    };

    public static AccessMatrixFile Load()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Matrix", "access-matrix.json");
        using var stream = File.OpenRead(path);
        return JsonSerializer.Deserialize<AccessMatrixFile>(stream, Options)
            ?? throw new InvalidOperationException("access-matrix.json is empty.");
    }

}
