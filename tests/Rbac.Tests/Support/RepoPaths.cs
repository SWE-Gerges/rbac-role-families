namespace Rbac.Tests.Support;

internal static class RepoPaths
{
    /// <summary>The repository root, found by walking up to the solution file so tests work from any checkout.</summary>
    public static string Root { get; } = FindRoot();

    public static string FromRoot(params string[] segments) => Path.Combine([Root, .. segments]);

    private static string FindRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "RbacRoleFamilies.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("RbacRoleFamilies.slnx was not found above " + AppContext.BaseDirectory);
    }
}
