using SkyIdentity;

namespace SkyIdentity.Tests;

public sealed class IdentityCoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "sky-identity-tests-" + Guid.NewGuid().ToString("N"));

    public IdentityCoreTests() => Directory.CreateDirectory(_directory);

    [Fact]
    public void RegistrationPersistsAndPasswordVerificationSurvivesReload()
    {
        var path = Path.Combine(_directory, "users.json");
        var now = DateTimeOffset.UtcNow;
        var store = new IdentityStore(path, 100_000);

        Assert.True(store.Register("Alice.Example", "correct horse battery staple", now, out var username));
        Assert.Equal("alice.example", username);
        Assert.False(store.Register("alice.example", "another long password", now, out _));
        Assert.True(File.Exists(path));
        Assert.DoesNotContain("correct horse battery staple", File.ReadAllText(path));

        var reloaded = new IdentityStore(path, 100_000);
        Assert.True(reloaded.Verify("alice.example", "correct horse battery staple", out var verified));
        Assert.Equal("alice.example", verified);
        Assert.False(reloaded.Verify("alice.example", "wrong password value", out _));
    }

    [Theory]
    [InlineData("ab")]
    [InlineData("UPPER SPACE")]
    [InlineData("../admin")]
    public void InvalidUsernamesAreRejected(string username)
    {
        Assert.Throws<ArgumentException>(() => IdentityValidation.NormalizeUsername(username));
    }

    [Fact]
    public void SessionTokensExpireAndCanBeRevoked()
    {
        var now = DateTimeOffset.UtcNow;
        var sessions = new SessionStore(TimeSpan.FromMinutes(5));
        var issued = sessions.Issue("alice", now);

        Assert.NotEqual(issued.Token, "alice");
        Assert.Equal("alice", sessions.Validate(issued.Token, now.AddMinutes(1))?.Username);
        Assert.True(sessions.Revoke(issued.Token));
        Assert.Null(sessions.Validate(issued.Token, now.AddMinutes(1)));

        var expiring = sessions.Issue("bob", now);
        Assert.Null(sessions.Validate(expiring.Token, now.AddMinutes(6)));
    }

    [Fact]
    public void MalformedPersistedDataFailsClosed()
    {
        var path = Path.Combine(_directory, "users.json");
        File.WriteAllText(path, "not-json");
        Assert.ThrowsAny<Exception>(() => new IdentityStore(path, 100_000));
    }

    public void Dispose()
    {
        try { Directory.Delete(_directory, true); } catch { }
    }
}
