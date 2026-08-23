using System.Collections.Concurrent;
using System.Security.Cryptography;
using SkyIdentity;

static int ReadInt(string name, int fallback, int min, int max)
{
    var raw = Environment.GetEnvironmentVariable(name);
    if (string.IsNullOrWhiteSpace(raw)) return fallback;
    if (!int.TryParse(raw, out var value) || value < min || value > max)
        throw new InvalidOperationException($"{name} must be an integer between {min} and {max}");
    return value;
}

static string? ReadBearer(HttpRequest request)
{
    var value = request.Headers.Authorization.ToString();
    const string prefix = "Bearer ";
    if (!value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return null;
    var token = value[prefix.Length..].Trim();
    return token.Length is >= 32 and <= 512 ? token : null;
}

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 32 * 1024;
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
    options.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(75);
});

var dataPath = Environment.GetEnvironmentVariable("IDENTITY_DATA_PATH") ?? Path.Combine("data", "users.json");
var iterations = ReadInt("PBKDF2_ITERATIONS", 210_000, 100_000, 2_000_000);
var sessionMinutes = ReadInt("SESSION_TTL_MINUTES", 60, 5, 1440);
var users = new IdentityStore(dataPath, iterations);
var sessions = new SessionStore(TimeSpan.FromMinutes(sessionMinutes));
var metrics = new IdentityMetrics();
var app = builder.Build();

app.Use(async (context, next) =>
{
    context.Response.Headers["Cache-Control"] = "no-store";
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    await next();
});

app.MapGet("/healthz", () => Results.Ok(new { status = "healthy", service = "sky-identity" }));
app.MapGet("/readyz", () => Results.Ok(new { status = "ready", service = "sky-identity", persistedUsers = users.Count, activeSessions = sessions.Count }));
app.MapGet("/metrics", () => Results.Ok(metrics.Snapshot(users.Count, sessions.Count)));

app.MapPost("/api/v1/register", (RegisterRequest input, ILogger<Program> logger) =>
{
    try
    {
        if (!users.Register(input.Username ?? "", input.Password ?? "", DateTimeOffset.UtcNow, out var username))
        {
            metrics.Increment("register_conflict");
            return Results.Conflict(new { error = "account already exists" });
        }
        metrics.Increment("registered");
        logger.LogInformation("identity_event=registered username={Username}", username);
        return Results.Created($"/api/v1/users/{Uri.EscapeDataString(username)}", new { status = "registered", username });
    }
    catch (ArgumentException ex)
    {
        metrics.Increment("validation_rejected");
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/v1/login", (LoginRequest input, ILogger<Program> logger) =>
{
    var suppliedPassword = input.Password ?? "";
    if (!users.Verify(input.Username ?? "", suppliedPassword, out var username))
    {
        metrics.Increment("login_rejected");
        logger.LogWarning("identity_event=login_rejected username={Username}", (input.Username ?? "").Trim().ToLowerInvariant());
        return Results.Json(new { error = "invalid credentials" }, statusCode: StatusCodes.Status401Unauthorized);
    }
    var issued = sessions.Issue(username, DateTimeOffset.UtcNow);
    metrics.Increment("login_succeeded");
    logger.LogInformation("identity_event=login_succeeded username={Username}", username);
    return Results.Ok(new { accessToken = issued.Token, tokenType = "Bearer", expiresAt = issued.Session.ExpiresAt, username });
});

app.MapGet("/api/v1/me", (HttpRequest request) =>
{
    var token = ReadBearer(request);
    if (token is null) return Results.Json(new { error = "unauthorized" }, statusCode: StatusCodes.Status401Unauthorized);
    var session = sessions.Validate(token, DateTimeOffset.UtcNow);
    if (session is null)
    {
        metrics.Increment("session_rejected");
        return Results.Json(new { error = "unauthorized" }, statusCode: StatusCodes.Status401Unauthorized);
    }
    return Results.Ok(new { username = session.Username, expiresAt = session.ExpiresAt });
});

app.MapPost("/api/v1/logout", (HttpRequest request, ILogger<Program> logger) =>
{
    var token = ReadBearer(request);
    if (token is null) return Results.Json(new { error = "unauthorized" }, statusCode: StatusCodes.Status401Unauthorized);
    var session = sessions.Validate(token, DateTimeOffset.UtcNow);
    if (session is null) return Results.Json(new { error = "unauthorized" }, statusCode: StatusCodes.Status401Unauthorized);
    sessions.Revoke(token);
    metrics.Increment("logout");
    logger.LogInformation("identity_event=logout username={Username}", session.Username);
    return Results.Ok(new { status = "logged_out" });
});

app.Run();

public sealed record RegisterRequest(string? Username, string? Password);
public sealed record LoginRequest(string? Username, string? Password);

public sealed class IdentityMetrics
{
    private readonly ConcurrentDictionary<string, long> _values = new(StringComparer.Ordinal);
    public void Increment(string name) => _values.AddOrUpdate(name, 1, (_, current) => current + 1);
    public IReadOnlyDictionary<string, object> Snapshot(int users, int sessions)
    {
        var result = _values.ToDictionary(pair => pair.Key, pair => (object)pair.Value, StringComparer.Ordinal);
        result["service"] = "sky-identity";
        result["persisted_users"] = users;
        result["active_sessions"] = sessions;
        return result;
    }
}

public partial class Program { }
