using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Rbac.IntegrationTests.Support;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests;

/// <summary>Fast checks on committed artefacts. They read files only and need no host.</summary>
public partial class RepositoryLayoutTests
{
    [GeneratedRegex(@"^(GET|POST|PUT|PATCH|DELETE)\s+\{\{baseUrl\}\}(\S+)", RegexOptions.Multiline)]
    private static partial Regex RequestLine();

    [Fact]
    public void The_committed_openapi_document_is_valid_json_with_paths()
    {
        var document = JsonNode.Parse(File.ReadAllText(RepoPaths.FromRoot("docs", "openapi.json")));

        document!["openapi"]!.GetValue<string>().ShouldStartWith("3.");
        document["paths"]!.AsObject().Count.ShouldBeGreaterThan(4);
    }

    [Fact]
    public void Every_documented_operation_has_a_request_in_the_http_file()
    {
        var document = JsonNode.Parse(File.ReadAllText(RepoPaths.FromRoot("docs", "openapi.json")))!;
        var http = File.ReadAllText(RepoPaths.FromRoot("requests", "rbac.http"));
        var requests = RequestLine().Matches(http).Select(m => (Method: m.Groups[1].Value, Path: m.Groups[2].Value)).ToArray();
        var missing = new List<string>();

        foreach (var (path, item) in document["paths"]!.AsObject())
        {
            // Match "/api/v1/bookings/{id}/cancel" against "/api/v1/bookings/{{bookingId}}/cancel" style requests.
            var shape = Regex.Replace(path, @"\{[^}]+\}", "*");
            foreach (var (method, _) in item!.AsObject())
            {
                var found = requests.Any(r =>
                    string.Equals(r.Method, method, StringComparison.OrdinalIgnoreCase)
                    && Regex.IsMatch(Regex.Replace(r.Path.Split('?')[0], @"\{\{[^}]+\}\}", "*"), "^" + Regex.Escape(shape).Replace(@"\*", "[^/]+") + "$"));
                if (!found)
                {
                    missing.Add($"{method.ToUpperInvariant()} {path}");
                }
            }
        }

        missing.ShouldBeEmpty("requests/rbac.http needs one request per endpoint");
    }
}
