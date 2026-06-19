using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Text.Json;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var users = new ConcurrentDictionary<string, string>(); // username -> hashed_password
var tokens = new ConcurrentDictionary<string, string>(); // token -> username

string HashPassword(string password) {
    using var sha256 = SHA256.Create();
    var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
    return Convert.ToHexString(bytes);
}

app.MapPost("/api/v1/register", async (HttpContext context) => {
    using var doc = await JsonDocument.ParseAsync(context.Request.Body);
    var root = doc.RootElement;
    var username = root.TryGetProperty("username", out var u) ? u.GetString() ?? "" : "";
    var password = root.TryGetProperty("password", out var p) ? p.GetString() ?? "" : "";
    if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password)) {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsJsonAsync(new { error = "Username and password required" });
        return;
    }
    users[username] = HashPassword(password);
    await context.Response.WriteAsJsonAsync(new { status = "registered", username });
});

app.MapPost("/api/v1/login", async (HttpContext context) => {
    using var doc = await JsonDocument.ParseAsync(context.Request.Body);
    var root = doc.RootElement;
    var username = root.TryGetProperty("username", out var u) ? u.GetString() ?? "" : "";
    var password = root.TryGetProperty("password", out var p) ? p.GetString() ?? "" : "";
    if (!users.TryGetValue(username, out var hash) || hash != HashPassword(password)) {
        context.Response.StatusCode = 401;
        await context.Response.WriteAsJsonAsync(new { error = "Invalid credentials" });
        return;
    }
    var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    tokens[token] = username;
    await context.Response.WriteAsJsonAsync(new { token, username });
});

app.MapGet("/health", () => new { status = "healthy" });

app.Run("http://0.0.0.0:8080");
