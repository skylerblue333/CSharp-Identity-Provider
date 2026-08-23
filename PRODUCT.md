# Sky Identity — Product Definition

Sky Identity is product #7 in the SKYCOIN4444 standalone-product roadmap.

## Product role

A small local-first identity service that safely owns account password records and issues revocable opaque bearer sessions. It is intended to provide a concrete authentication boundary for SKYCOIN4444 development, staging and controlled self-hosted deployments while later federation standards are added through adapters.

## Commercially useful capability

- deployable account-registration/login service;
- persisted password credential database;
- opaque session authentication for downstream applications;
- operational health/readiness/metrics;
- container packaging and automated tests.

## Explicit non-claims

This release is not called an OAuth/OIDC provider, enterprise SSO suite, passwordless identity system, compliance-certified IdP, globally replicated session service or managed identity cloud. Those labels require additional protocol and deployment evidence.

## Productization gate

The release branch must pass exact-head build, xUnit tests, dependency-vulnerability reporting, container build and non-root declaration checks. Completion is declared only after merge and default-branch read-back.

## Future integration

Sky Gateway should call Sky Identity through documented HTTP/service contracts. Future OAuth/OIDC and SAML work should wrap standards-tested upstream libraries or dedicated components rather than inventing cryptographic/protocol primitives in this repository.
