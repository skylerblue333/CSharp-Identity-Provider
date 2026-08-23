using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SkyIdentity;

public sealed record UserRecord(
    string Username,
    string SaltBase64,
    string PasswordHashBase64,
    DateTimeOffset CreatedAt,
    bool Disabled = false
);

public sealed record SessionInfo(string Username, DateTimeOffset ExpiresAt);

public static partial class IdentityValidation
{
    [GeneratedRegex("^[a-z0-9][a-z0-9._-]{2,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex UsernameRegex();

    public static string NormalizeUsername(string value)
    {
        var username = value.Trim().ToLowerInvariant();
        if (!UsernameRegex().IsMatch(username))
            throw new ArgumentException("username must be 3-64 characters using lowercase letters, numbers, dot, underscore, or hyphen");
        return username;
    }

    public static void ValidatePassword(string password)
    {
        if (password.Length is < 12 or > 256)
            throw new ArgumentException("password must be between 12 and 256 characters");
    }
}

public static class PasswordHasher
{
    public const int SaltBytes = 16;
    public const int HashBytes = 32;

    public static UserRecord Create(string username, string password, int iterations, DateTimeOffset now)
    {
        IdentityValidation.ValidatePassword(password);
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Derive(password, salt, iterations);
        try
        {
            return new UserRecord(
                username,
                Convert.ToBase64String(salt),
                Convert.ToBase64String(hash),
                now
            );
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    public static bool Verify(UserRecord user, string password, int iterations)
    {
        byte[] salt;
        byte[] expected;
        try
        {
            salt = Convert.FromBase64String(user.SaltBase64);
            expected = Convert.FromBase64String(user.PasswordHashBase64);
        }
        catch (FormatException)
        {
            return false;
        }

        var actual = Derive(password, salt, iterations);
        try
        {
            return expected.Length == actual.Length && CryptographicOperations.FixedTimeEquals(expected, actual);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    public static void RunDummyVerification(string password, int iterations)
    {
        var salt = SHA256.HashData(Encoding.UTF8.GetBytes("sky-identity-dummy-login-salt"))[..SaltBytes];
        var actual = Derive(password, salt, iterations);
        CryptographicOperations.ZeroMemory(actual);
    }

    private static byte[] Derive(string password, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            HashBytes
        );
}

public sealed class IdentityStore
{
    private readonly string _path;
    private readonly int _iterations;
    private readonly object _gate = new();
    private Dictionary<string, UserRecord> _users = new(StringComparer.Ordinal);

    public IdentityStore(string path, int iterations)
    {
        _path = Path.GetFullPath(path);
        _iterations = iterations;
        Load();
    }

    public int Count
    {
        get { lock (_gate) return _users.Count; }
    }

    public bool Register(string rawUsername, string password, DateTimeOffset now, out string username)
    {
        username = IdentityValidation.NormalizeUsername(rawUsername);
        var record = PasswordHasher.Create(username, password, _iterations, now);
        lock (_gate)
        {
            if (_users.ContainsKey(username))
                return false;
            _users[username] = record;
            PersistLocked();
            return true;
        }
    }

    public bool Verify(string rawUsername, string password, out string username)
    {
        username = rawUsername.Trim().ToLowerInvariant();
        UserRecord? user;
        lock (_gate)
            _users.TryGetValue(username, out user);

        if (user is null)
        {
            PasswordHasher.RunDummyVerification(password, _iterations);
            return false;
        }
        return !user.Disabled && PasswordHasher.Verify(user, password, _iterations);
    }

    private void Load()
    {
        lock (_gate)
        {
            if (!File.Exists(_path))
            {
                _users = new Dictionary<string, UserRecord>(StringComparer.Ordinal);
                return;
            }
            var json = File.ReadAllText(_path, Encoding.UTF8);
            var records = JsonSerializer.Deserialize<List<UserRecord>>(json)
                ?? throw new InvalidDataException("identity store must contain a JSON array");
            _users = records.ToDictionary(u => u.Username, StringComparer.Ordinal);
        }
    }

    private void PersistLocked()
    {
        var directory = Path.GetDirectoryName(_path) ?? ".";
        Directory.CreateDirectory(directory);
        var temp = _path + ".tmp-" + Guid.NewGuid().ToString("N");
        var payload = JsonSerializer.Serialize(_users.Values.OrderBy(u => u.Username), new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(temp, payload, new UTF8Encoding(false));
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.Move(temp, _path, true);
    }
}

public sealed class SessionStore
{
    private readonly TimeSpan _ttl;
    private readonly ConcurrentDictionary<string, SessionInfo> _sessions = new(StringComparer.Ordinal);

    public SessionStore(TimeSpan ttl) => _ttl = ttl;

    public int Count => _sessions.Count;

    public (string Token, SessionInfo Session) Issue(string username, DateTimeOffset now)
    {
        Cleanup(now);
        var tokenBytes = RandomNumberGenerator.GetBytes(32);
        var token = Convert.ToHexString(tokenBytes);
        CryptographicOperations.ZeroMemory(tokenBytes);
        var session = new SessionInfo(username, now.Add(_ttl));
        _sessions[HashToken(token)] = session;
        return (token, session);
    }

    public SessionInfo? Validate(string token, DateTimeOffset now)
    {
        Cleanup(now);
        var key = HashToken(token);
        if (!_sessions.TryGetValue(key, out var session) || session.ExpiresAt <= now)
        {
            _sessions.TryRemove(key, out _);
            return null;
        }
        return session;
    }

    public bool Revoke(string token) => _sessions.TryRemove(HashToken(token), out _);

    private void Cleanup(DateTimeOffset now)
    {
        foreach (var pair in _sessions)
            if (pair.Value.ExpiresAt <= now)
                _sessions.TryRemove(pair.Key, out _);
    }

    private static string HashToken(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}
