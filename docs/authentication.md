# Authentication

The Attestation Server uses **OIDC bearer tokens** for authentication.
Every request must include an `Authorization: Bearer <token>` header
with a valid token containing the required role.

## Required role

| Role                         | Grants access to |
|------------------------------|------------------|
| `attestation-server:client`  | `POST /`         |

## OIDC provider setup

1. **Create a project** in your OIDC provider (Zitadel, Keycloak, Auth0, etc.)
2. **Define the role** `attestation-server:client`
3. **Create a service account** (or user) and assign the role
4. **Generate a token** — either a long-lived service account token or
   use the client credentials flow

### Zitadel example

```
Project: attestation-server
Role:    attestation-server:client
```

Assign the role to a service user, then generate a JWT or PAT.

### Keycloak example

Create a realm role `attestation-server:client` and assign it to the
client or user. The role appears in `realm_access.roles`.

## Server configuration

```bash
attestation-server \
  --oidc-issuer https://auth.example.com \
  --oidc-audience attestation-server
```

Or via environment variables:

```bash
OIDC_ISSUER=https://auth.example.com \
OIDC_AUDIENCE=attestation-server \
  attestation-server
```

## Role claim formats

The server checks three claim paths to support multiple OIDC providers:

### 1. Zitadel (default claim)

```json
{
  "urn:zitadel:iam:org:project:roles": {
    "attestation-server:client": { "orgId": "..." }
  }
}
```

### 2. Standard `roles` array

```json
{
  "roles": ["attestation-server:client"]
}
```

### 3. Keycloak `realm_access`

```json
{
  "realm_access": {
    "roles": ["attestation-server:client"]
  }
}
```

## Using the token

Pass it in the `Authorization` header of every request:

```
Authorization: Bearer eyJhbGciOiJSUzI1NiI...
```

### curl example

```bash
curl -X POST https://as.privasys.org/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"quote": "<base64-encoded-quote>"}'
```

### Enclave integration

Enclaves receive their attestation server token via the management API.
The egress module automatically includes the `Authorization` header
when verifying quotes against authenticated attestation servers.

## JWKS caching

The server caches JWKS keys for 5 minutes per issuer. On first request
(or after cache expiry), it performs OIDC discovery:

1. `GET <issuer>/.well-known/openid-configuration` → extracts `jwks_uri`
2. `GET <jwks_uri>` → fetches signing keys

Both requests have a 10-second timeout.

## Multi-issuer support

The server can trust multiple OIDC issuers simultaneously. Set
`OIDC_ISSUER` to a comma-separated list:

```bash
OIDC_ISSUER=https://auth.example.com,https://broker.example.com
```

Each issuer maintains its own independent JWKS cache. When validating a
token, the server extracts the `iss` claim and looks up the matching
issuer's cached keys. Tokens from unrecognized issuers are rejected.

This is used in production to accept tokens from both the platform
identity provider and the auth broker's app attestation token flow.
