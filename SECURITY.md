# Security Model — Sky Identity

## Implemented controls

- Passwords are never persisted in plaintext. They are derived with PBKDF2-HMAC-SHA256 using a per-user random 128-bit salt.
- Password hashes are compared with `CryptographicOperations.FixedTimeEquals`.
- Unknown-user login attempts execute a dummy password derivation before returning the same generic invalid-credentials response.
- Opaque access tokens are generated from 256 bits of cryptographic randomness.
- Only SHA-256 digests of active session tokens are kept in server memory; plaintext tokens are returned once to the caller.
- Sessions expire and can be explicitly revoked through logout.
- Persisted user records are replaced atomically and use user-only Unix permissions where the platform supports them.
- Malformed persisted data fails service startup rather than silently resetting the account database.
- Request bodies are bounded at the Kestrel layer.
- Sensitive responses carry `Cache-Control: no-store`; security events do not intentionally log passwords or access tokens.
- The container runs as the .NET non-root `app` user and stores mutable account data under `/data`.

## Important limitations

This is not an OAuth 2.0/OpenID Connect certification target yet. It does not implement authorization-code/PKCE flows, refresh tokens, JWKS/JWT signing, MFA, password recovery, account lockout, breached-password screening, SAML, SCIM, external directory sync, HSM/KMS custody, distributed sessions or HA replication.

PBKDF2 iterations are configuration-sensitive. Production operators should benchmark an appropriate work factor on their hardware and increase it over time without exceeding acceptable login latency.

The JSON account store is designed for a single-writer service instance. Multi-instance production deployment requires a transactional shared identity datastore before HA can be claimed.

## Secret handling

Do not log passwords or returned access tokens. Protect the data volume and deployment environment. Terminate TLS before exposing the service over an untrusted network.

## Reporting

Use private security reporting when available. Never place credentials, user databases, private keys or live access tokens in public issues.
