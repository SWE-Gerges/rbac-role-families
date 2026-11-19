using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Rbac.Demo.Contracts;

namespace Rbac.IntegrationTests.Support;

public static class ApiHelpers
{
    /// <summary>Reads every page of the caller's booking list and returns the ids in the order returned.</summary>
    public static async Task<(HttpStatusCode Status, IReadOnlyList<string> Ids)> ListIdsAsync(HttpClient client, string query = "")
    {
        var ids = new List<string>();
        var page = 1;
        while (true)
        {
            var separator = query.Length > 0 ? "&" : string.Empty;
            var response = await client.GetAsync($"/api/v1/bookings?{query}{separator}pageSize=100&page={page}");
            if (response.StatusCode != HttpStatusCode.OK)
            {
                return (response.StatusCode, []);
            }

            var body = await response.Content.ReadFromJsonAsync<BookingListResponse>(ApiFactory.Json)
                ?? throw new InvalidOperationException("Empty list response.");
            ids.AddRange(body.Items.Select(i => i.Id));
            if (ids.Count >= body.TotalCount || body.Items.Count == 0)
            {
                return (HttpStatusCode.OK, ids);
            }

            page++;
        }
    }

    public static async Task<(HttpStatusCode Status, IReadOnlyList<string> Ids)> ListUserIdsAsync(HttpClient client, string query = "")
    {
        var ids = new List<string>();
        var page = 1;
        while (true)
        {
            var separator = query.Length > 0 ? "&" : string.Empty;
            var response = await client.GetAsync($"/api/v1/users?{query}{separator}pageSize=100&page={page}");
            if (response.StatusCode != HttpStatusCode.OK)
            {
                return (response.StatusCode, []);
            }

            var body = await response.Content.ReadFromJsonAsync<UserListResponse>(ApiFactory.Json)
                ?? throw new InvalidOperationException("Empty list response.");
            ids.AddRange(body.Items.Select(i => i.Id));
            if (ids.Count >= body.TotalCount || body.Items.Count == 0)
            {
                return (HttpStatusCode.OK, ids);
            }

            page++;
        }
    }

    public static async Task<UserResponse> CreateUserAsync(HttpClient client, string handle, string roleKey, string? agencyId = null, string? corporateId = null)
    {
        var response = await client.PostAsJsonAsync("/api/v1/users", new CreateUserRequest(handle, handle, roleKey, agencyId, corporateId), ApiFactory.Json);
        if (response.StatusCode != HttpStatusCode.Created)
        {
            throw new InvalidOperationException($"Create user failed with {(int)response.StatusCode}: {await response.Content.ReadAsStringAsync()}");
        }

        return await response.ReadAsAsync<UserResponse>();
    }

    public static async Task<JsonElement> ReadJsonAsync(this HttpResponseMessage response)
    {
        var text = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    public static async Task<T> ReadAsAsync<T>(this HttpResponseMessage response) =>
        await response.Content.ReadFromJsonAsync<T>(ApiFactory.Json)
            ?? throw new InvalidOperationException("Empty response body.");

    public static async Task<BookingResponse> CreateBookingAsync(HttpClient client, string type = "Hotel", decimal amount = 100m)
    {
        var response = await client.PostAsJsonAsync("/api/v1/bookings", new { type, amount }, ApiFactory.Json);
        if (response.StatusCode != HttpStatusCode.Created)
        {
            throw new InvalidOperationException($"Create failed with {(int)response.StatusCode}: {await response.Content.ReadAsStringAsync()}");
        }

        return await response.ReadAsAsync<BookingResponse>();
    }
}
