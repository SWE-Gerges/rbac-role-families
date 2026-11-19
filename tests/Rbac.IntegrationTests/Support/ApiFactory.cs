using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Rbac.Demo.Contracts;
using Rbac.Persistence;

namespace Rbac.IntegrationTests.Support;

/// <summary>
/// A SQLite database that several hosts can open at once. <see cref="CreateFile"/> makes a WAL-mode file (what a second
/// application instance would share); the default is a named shared-cache in-memory database that lives while this object does.
/// </summary>
public sealed class SharedSqliteDatabase : IDisposable
{
    private readonly SqliteConnection? _keepAlive;
    private readonly string? _path;

    public SharedSqliteDatabase()
    {
        ConnectionString = $"Data Source=file:rbac-{Guid.NewGuid():N}?mode=memory&cache=shared";
        _keepAlive = new SqliteConnection(ConnectionString);
        _keepAlive.Open();
    }

    private SharedSqliteDatabase(string path)
    {
        _path = path;
        ConnectionString = $"Data Source={path};Pooling=False";
        using var connection = new SqliteConnection(ConnectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL;";
        command.ExecuteNonQuery();
    }

    public string ConnectionString { get; }

    /// <summary>A database file next to the test binaries (git ignores <c>*.db</c>), removed together with its WAL files on dispose.</summary>
    public static SharedSqliteDatabase CreateFile() =>
        new(Path.Combine(AppContext.BaseDirectory, $"rbac-shared-{Guid.NewGuid():N}.db"));

    /// <summary>Runs SQL straight on the database, the way an operator editing data would.</summary>
    public async Task ExecuteAsync(string sql)
    {
        await using var connection = await OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }

    public async Task<long> ScalarAsync(string sql)
    {
        await using var connection = await OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture);
    }

    public void Dispose()
    {
        _keepAlive?.Dispose();
        if (_path is null)
        {
            return;
        }

        SqliteConnection.ClearAllPools();
        foreach (var file in new[] { _path, _path + "-wal", _path + "-shm" })
        {
            File.Delete(file);
        }
    }

    private async Task<SqliteConnection> OpenAsync()
    {
        if (_keepAlive is not null && _path is null)
        {
            // In-memory databases are shared through the cache name, so a separate connection sees the same data.
            var shared = new SqliteConnection(ConnectionString);
            await shared.OpenAsync();
            return shared;
        }

        var connection = new SqliteConnection(ConnectionString);
        await connection.OpenAsync();
        return connection;
    }
}

public sealed class ApiFactoryOptions
{
    /// <summary>Share one database between factories. When null the factory creates and owns a private one.</summary>
    public SharedSqliteDatabase? Database { get; init; }

    /// <summary>Replace the clock the host uses for audit timestamps, token lifetimes and cache decisions.</summary>
    public TimeProvider? Clock { get; init; }

    public bool EnableDevTokens { get; init; } = true;

    public Action<IServiceCollection>? ConfigureServices { get; init; }

    public CapturingLoggerProvider? Logs { get; init; }

    public IReadOnlyDictionary<string, string?> Settings { get; init; } = new Dictionary<string, string?>();
}

/// <summary>Hosts the demo API in memory on SQLite: a private in-memory database per factory, or one shared with other factories.</summary>
public sealed class ApiFactory : WebApplicationFactory<Program>
{
    public const string SigningKey = "integration-test-signing-key-0123456789";
    public const string Issuer = "rbac-demo";
    public const string Audience = "rbac-demo-api";

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly ApiFactoryOptions _options;
    private readonly SharedSqliteDatabase _database;
    private readonly bool _ownsDatabase;
    private readonly ConcurrentDictionary<string, string> _tokens = new(StringComparer.Ordinal);

    public ApiFactory()
        : this(new ApiFactoryOptions())
    {
    }

    internal ApiFactory(ApiFactoryOptions options)
    {
        _options = options;
        _ownsDatabase = options.Database is null;
        _database = options.Database ?? new SharedSqliteDatabase();
    }

    public static ApiFactory With(ApiFactoryOptions options) => new(options);

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureAppConfiguration((_, config) =>
        {
            var settings = new Dictionary<string, string?>
            {
                ["Persistence:Provider"] = nameof(DatabaseProvider.Sqlite),
                ["Persistence:ConnectionString"] = _database.ConnectionString,
                ["Persistence:SeedDemoData"] = "true",
                ["Demo:EnableDevTokens"] = _options.EnableDevTokens ? "true" : "false",
                ["Demo:Jwt:SigningKey"] = SigningKey,
                ["Demo:Jwt:Issuer"] = Issuer,
                ["Demo:Jwt:Audience"] = Audience,
            };
            foreach (var (key, value) in _options.Settings)
            {
                settings[key] = value;
            }

            config.AddInMemoryCollection(settings);
        });

        if (_options.Logs is { } logs)
        {
            builder.ConfigureLogging(logging => logging.AddProvider(logs));
        }

        if (_options.Clock is { } clock)
        {
            builder.ConfigureServices(services => services.AddSingleton(clock));
        }

        if (_options.ConfigureServices is { } configure)
        {
            builder.ConfigureServices(configure);
        }
    }

    /// <summary>A token for a seeded user, issued by the demo's dev endpoint and cached for the life of the factory.</summary>
    public async Task<string> TokenForAsync(string userId, bool fresh = false)
    {
        if (!fresh && _tokens.TryGetValue(userId, out var cached))
        {
            return cached;
        }

        using var client = CreateClient();
        var response = await client.PostAsJsonAsync("/api/v1/dev/token", new DevTokenRequest(userId), Json);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<DevTokenResponse>(Json)
            ?? throw new InvalidOperationException("Empty token response.");
        _tokens[userId] = body.AccessToken;
        return body.AccessToken;
    }

    public async Task<HttpClient> ClientForAsync(string userId, bool freshToken = false)
    {
        var client = CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await TokenForAsync(userId, freshToken));
        return client;
    }

    public HttpClient ClientWithToken(string token)
    {
        var client = CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    /// <summary>Runs SQL straight on the SQLite database, the way an operator editing data would.</summary>
    public Task ExecuteSqliteAsync(string sql) => _database.ExecuteAsync(sql);

    public Task<long> ScalarSqliteAsync(string sql) => _database.ScalarAsync(sql);

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && _ownsDatabase)
        {
            _database.Dispose();
        }
    }
}
