namespace Rbac.Demo;

/// <summary>
/// The client channel header. It is a presentation hint only and is never an authorization input:
/// nothing that decides what a caller may see reads it.
/// </summary>
internal static class ChannelHint
{
    public const string HeaderName = "X-Client-Channel";

    private static readonly string[] Known = ["web", "app", "back-office"];

    public static string? Parse(string? header) =>
        Known.FirstOrDefault(k => string.Equals(k, header?.Trim(), StringComparison.OrdinalIgnoreCase));
}
