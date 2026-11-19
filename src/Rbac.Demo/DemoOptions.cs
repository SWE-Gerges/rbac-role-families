using System.Text;
using Microsoft.Extensions.Options;

namespace Rbac.Demo;

public sealed class DemoOptions
{
    public const string SectionName = "Demo";

    /// <summary>Demo only. Enables <c>POST /api/v1/dev/token</c>, which issues a token for any seeded user without credentials.</summary>
    public bool EnableDevTokens { get; set; }

    public JwtSettings Jwt { get; set; } = new();
}

public sealed class JwtSettings
{
    /// <summary>HS256 needs at least 32 bytes of key material.</summary>
    public const int MinimumKeyBytes = 32;

    public string Issuer { get; set; } = string.Empty;

    public string Audience { get; set; } = string.Empty;

    public string SigningKey { get; set; } = string.Empty;

    public int TokenLifetimeMinutes { get; set; } = 60;
}

internal sealed class DemoOptionsValidator : IValidateOptions<DemoOptions>
{
    public ValidateOptionsResult Validate(string? name, DemoOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Jwt.Issuer))
        {
            failures.Add("Demo:Jwt:Issuer is required.");
        }

        if (string.IsNullOrWhiteSpace(options.Jwt.Audience))
        {
            failures.Add("Demo:Jwt:Audience is required.");
        }

        if (Encoding.UTF8.GetByteCount(options.Jwt.SigningKey ?? string.Empty) < JwtSettings.MinimumKeyBytes)
        {
            failures.Add($"Demo:Jwt:SigningKey must be at least {JwtSettings.MinimumKeyBytes} bytes.");
        }

        if (options.Jwt.TokenLifetimeMinutes is < 1 or > 1440)
        {
            failures.Add("Demo:Jwt:TokenLifetimeMinutes must be between 1 and 1440.");
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
