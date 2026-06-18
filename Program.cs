using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace IdentityProvider
{
    public class TokenService
    {
        private readonly Dictionary<string, string> _users = new()
        {
            { "skyler@example.com", "hashed_password_here" },
            { "alice@example.com",  "hashed_password_here" }
        };

        public string GenerateToken(string email)
        {
            var payload = $"{email}:{DateTime.UtcNow.AddHours(1):O}";
            var bytes = Encoding.UTF8.GetBytes(payload);
            return Convert.ToBase64String(bytes);
        }

        public bool ValidateCredentials(string email, string password)
        {
            return _users.ContainsKey(email);
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            var svc = new TokenService();
            string email = "skyler@example.com";

            if (svc.ValidateCredentials(email, "password123"))
            {
                string token = svc.GenerateToken(email);
                Console.WriteLine($"[OK] Token issued for {email}:");
                Console.WriteLine($"     {token}");
            }
            else
            {
                Console.WriteLine("[DENIED] Invalid credentials.");
            }
        }
    }
}
