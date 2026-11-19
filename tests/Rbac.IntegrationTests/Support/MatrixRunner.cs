using System.Net;
using System.Net.Http.Json;

namespace Rbac.IntegrationTests.Support;

/// <summary>Replays the committed access matrix against a running API and reports every mismatch.</summary>
public static class MatrixRunner
{
    public static async Task<List<string>> RunListRowsAsync(ApiFactory factory, AccessMatrixFile matrix)
    {
        var failures = new List<string>();

        foreach (var row in matrix.List)
        {
            using var client = await factory.ClientForAsync(row.User);
            var (status, ids) = await ApiHelpers.ListIdsAsync(client, row.Query);

            if ((int)status != row.ExpectedStatus)
            {
                failures.Add($"{row.User} [{row.Scenario}]: expected {row.ExpectedStatus} but got {(int)status}");
                continue;
            }

            if (row.ExpectedStatus != 200)
            {
                continue;
            }

            if (ids.Count != ids.Distinct().Count())
            {
                failures.Add($"{row.User} [{row.Scenario}]: duplicate ids across pages");
            }

            var actual = ids.Order(StringComparer.Ordinal).ToArray();
            var expected = row.BookingIds!.Order(StringComparer.Ordinal).ToArray();
            if (!actual.SequenceEqual(expected))
            {
                failures.Add(
                    $"{row.User} [{row.Scenario}]: missing [{string.Join(", ", expected.Except(actual))}] unexpected [{string.Join(", ", actual.Except(expected))}]");
            }
        }

        return failures;
    }

    public static async Task<List<string>> RunUserListRowsAsync(ApiFactory factory, AccessMatrixFile matrix)
    {
        var failures = new List<string>();

        foreach (var row in matrix.Users)
        {
            using var client = await factory.ClientForAsync(row.User);
            var (status, ids) = await ApiHelpers.ListUserIdsAsync(client);

            if ((int)status != row.ExpectedStatus)
            {
                failures.Add($"{row.User} [{row.Scenario}]: expected {row.ExpectedStatus} but got {(int)status}");
                continue;
            }

            if (row.ExpectedStatus == 200)
            {
                var actual = ids.Order(StringComparer.Ordinal).ToArray();
                var expected = row.UserIds!.Order(StringComparer.Ordinal).ToArray();
                if (!actual.SequenceEqual(expected))
                {
                    failures.Add($"{row.User} [{row.Scenario}]: missing [{string.Join(", ", expected.Except(actual))}] unexpected [{string.Join(", ", actual.Except(expected))}]");
                }
            }
        }

        return failures;
    }

    public static async Task<List<string>> RunActionRowsAsync(ApiFactory factory, AccessMatrixFile matrix)
    {
        var failures = new List<string>();

        foreach (var row in matrix.Actions)
        {
            using var client = await factory.ClientForAsync(row.User);
            using var request = new HttpRequestMessage(new HttpMethod(row.Method), row.Path);
            if (row.Body is { } body)
            {
                request.Content = JsonContent.Create(body);
            }

            using var response = await client.SendAsync(request);
            if ((int)response.StatusCode != row.ExpectedStatus)
            {
                failures.Add($"{row.User} [{row.Scenario}] {row.Method} {row.Path}: expected {row.ExpectedStatus} but got {(int)response.StatusCode}");
            }
        }

        return failures;
    }

    public static bool IsProblem(HttpResponseMessage response) =>
        response.Content.Headers.ContentType?.MediaType == "application/problem+json" && response.StatusCode >= HttpStatusCode.BadRequest;
}
