# Sky Identity

**SKYCOIN4444 standalone product #7** — a compact C#/.NET identity service with persistent user records and short-lived opaque bearer sessions.

This repository does **not** claim to be a complete OAuth 2.0 or OpenID Connect provider. It is a focused identity foundation intended to sit behind Sky Gateway and later gain standards-based federation through explicit adapters.

## Implemented capability

- normalized account registration with duplicate protection;
- PBKDF2-HMAC-SHA256 password hashing with per-user random salts;
- constant-time password-hash comparison;
- dummy password derivation for unknown users to reduce obvious login timing differences;
- persistent JSON user store with atomic replacement and restrictive Unix file mode where supported;
- cryptographically random opaque bearer sessions;
- session tokens stored only as SHA-256 digests in server memory;
- configurable session expiry and logout/revocation;
- generic invalid-credential responses;
- `/api/v1/me` authenticated session inspection;
- startup validation for password-derivation and session settings;
- Kestrel request-body and timeout boundaries;
- `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and strict referrer response headers;
- structured security events that avoid logging passwords or session tokens;
- `/healthz`, `/readyz`, and lightweight `/metrics` endpoints;
- non-root .NET 8 container with persistent `/data` volume;
- xUnit coverage for persistence, password verification, validation, expiry, revocation and malformed-store failure;
- CI build, tests, dependency-vulnerability reporting and container-user verification.

## Run locally

```bash
dotnet run --project CSharp-Identity-Provider.csproj
```

Optional configuration:

```bash
export IDENTITY_DATA_PATH=./data/users.json
export PBKDF2_ITERATIONS=210000
export SESSION_TTL_MINUTES=60
```

Register and authenticate:

```bash
curl -X POST http://localhost:5000/api/v1/register \
  -H 'content-type: application/json' \
  -d '{"username":"alice.example","password":"correct horse battery staple"}'

curl -X POST http://localhost:5000/api/v1/login \
  -H 'content-type: application/json' \
  -d '{"username":"alice.example","password":"correct horse battery staple"}'
```

Use the returned opaque token:

```bash
curl http://localhost:5000/api/v1/me -H 'Authorization: Bearer <token>'
```

## Verify

```bash
dotnet restore tests/SkyIdentity.Tests.csproj
dotnet build CSharp-Identity-Provider.csproj -c Release --no-restore
dotnet test tests/SkyIdentity.Tests.csproj -c Release --no-restore
dotnet list tests/SkyIdentity.Tests.csproj package --vulnerable --include-transitive
docker build -t sky-identity .
```

## Container

```bash
docker build -t sky-identity .
docker run --rm -p 8080:8080 -v sky-identity-data:/data sky-identity
```

## Architecture

```text
Client
  │
  ▼
Sky Gateway
  │
  ▼
Sky Identity
  ├─ username/password validation
  ├─ PBKDF2 password verification
  ├─ persistent user records
  └─ in-memory opaque sessions
          │
          └─ downstream SKYCOIN4444 services
```

## Deliberate boundaries

Read [`SECURITY.md`](SECURITY.md), [`PRODUCT.md`](PRODUCT.md), and [`MASTER_PLAN.md`](MASTER_PLAN.md).

This implementation does not yet provide OAuth/OIDC authorization-code flows, JWT signing/JWKS, refresh tokens, MFA, password-reset/email verification, SAML federation, external directory sync, distributed session state, HSM/KMS key custody, or multi-region HA. Those capabilities must be implemented and tested before they are claimed.

## License

See [`LICENSE`](LICENSE).
