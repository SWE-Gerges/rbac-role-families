using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

[Trait("Category", "Integration")]
public class OpenApiSnapshotTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private const string UpdateVariable = "UPDATE_OPENAPI_SNAPSHOT";

    private const string RegenerateHint =
        "Regenerate it with:  UPDATE_OPENAPI_SNAPSHOT=1 dotnet test --project tests/Rbac.IntegrationTests --filter \"FullyQualifiedName~OpenApiSnapshotTests\"  "
        + "(PowerShell: $env:UPDATE_OPENAPI_SNAPSHOT=1; dotnet test --project tests/Rbac.IntegrationTests --filter \"FullyQualifiedName~OpenApiSnapshotTests\")";

    private async Task<string> GenerateAsync()
    {
        using var client = await factory.ClientForAsync(SeedIds.SystemAdminA);
        var response = await client.GetAsync("/openapi/v1.json");
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync();
    }

    [Fact]
    public async Task The_generated_document_matches_the_committed_docs_openapi_json()
    {
        var generated = await GenerateAsync();
        var path = RepoPaths.FromRoot("docs", "openapi.json");

        if (Environment.GetEnvironmentVariable(UpdateVariable) == "1")
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var pretty = JsonSerializer.Serialize(JsonNode.Parse(generated), new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
            await File.WriteAllTextAsync(path, pretty.ReplaceLineEndings("\n") + "\n", TestContext.Current.CancellationToken);
            return;
        }

        File.Exists(path).ShouldBeTrue($"docs/openapi.json is missing. {RegenerateHint}");
        var committed = JsonNode.Parse(await File.ReadAllTextAsync(path, TestContext.Current.CancellationToken));

        JsonNode.DeepEquals(committed, JsonNode.Parse(generated))
            .ShouldBeTrue($"docs/openapi.json is out of date. {RegenerateHint}");
    }

    [Fact]
    public async Task The_document_describes_every_endpoint_the_demo_maps_and_a_bearer_scheme()
    {
        var document = JsonNode.Parse(await GenerateAsync())!;
        var paths = document["paths"]!.AsObject();

        paths.Select(p => p.Key).Order().ShouldBe(
        [
            "/api/v1/access-matrix",
            "/api/v1/audit",
            "/api/v1/bookings",
            "/api/v1/bookings/{id}",
            "/api/v1/bookings/{id}/cancel",
            "/api/v1/dev/token",
            "/api/v1/me",
            "/api/v1/permissions",
            "/api/v1/roles",
            "/api/v1/roles/{key}",
            "/api/v1/roles/{key}/permissions",
            "/api/v1/users",
            "/api/v1/users/{id}",
            "/api/v1/users/{id}/permissions",
            "/api/v1/users/{id}/role",
        ]);
        document["components"]!["securitySchemes"]!["Bearer"]!["scheme"]!.GetValue<string>().ShouldBe("bearer");
        paths["/api/v1/bookings"]!["get"]!["security"].ShouldNotBeNull();
        paths["/api/v1/dev/token"]!["post"]!["security"].ShouldBeNull("the dev token issuer is anonymous");
        paths["/api/v1/dev/token"]!["post"]!["summary"]!.GetValue<string>().ShouldContain("DEMO ONLY");
    }
}
