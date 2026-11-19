using Rbac.Core.Tokens;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Registry;

public class TokenVersionStoreTests
{
    private readonly InMemoryTokenVersionStore _store = new();

    [Fact]
    public async Task A_user_that_was_never_bumped_is_on_version_one()
    {
        (await _store.GetCurrentVersionAsync("t1", "u1", CancellationToken.None)).ShouldBe(1);
    }

    [Fact]
    public async Task Bumping_increments_only_that_user_in_that_tenant()
    {
        (await _store.BumpAsync("t1", "u1", CancellationToken.None)).ShouldBe(2);

        (await _store.GetCurrentVersionAsync("t1", "u1", CancellationToken.None)).ShouldBe(2);
        (await _store.GetCurrentVersionAsync("t1", "u2", CancellationToken.None)).ShouldBe(1);
        (await _store.GetCurrentVersionAsync("t2", "u1", CancellationToken.None)).ShouldBe(1);
    }

    [Fact]
    public async Task Concurrent_bumps_are_never_lost()
    {
        const int bumps = 500;

        await Task.WhenAll(Enumerable.Range(0, bumps)
            .Select(_ => Task.Run(async () => await _store.BumpAsync("t1", "u1", CancellationToken.None), TestContext.Current.CancellationToken)));

        (await _store.GetCurrentVersionAsync("t1", "u1", CancellationToken.None)).ShouldBe(1 + bumps);
    }
}
